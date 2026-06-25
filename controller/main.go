// audit-resync: OpenBao HTTP audit device -> ESO resync trigger.
//
// Flow: OpenBao writes a KV secret -> emits an audit "response" event to this
// controller -> we filter to successful KV writes, derive the ESO key, find the
// ExternalSecret(s) bound to the openbao store that reference that key, and
// force ESO to resync (annotate) or delete the target Secret. ESO rewrites the
// Secret with the latest version; Stakater Reloader restarts the workload.
//
// Design constraints:
//   - OpenBao audit is SYNCHRONOUS + fail-closed: the audit POST sits in the
//     critical path of every OpenBao request. So the HTTP handler does the
//     minimum (parse + cheap filter) and returns 200 immediately; all k8s work
//     happens on a background worker. If the queue is full we DROP (a missed
//     trigger is recovered by ESO's refreshInterval; blocking OpenBao is worse).
//   - Stdlib only: tiny static binary, fast cold start, trivial build.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- config ----------

type config struct {
	listenAddr  string
	action      string // "force-sync" | "delete"
	dryRun      bool
	allowNS     map[string]bool // empty => all namespaces eligible
	storeName   string          // only act on ExternalSecrets bound to this store
	esCacheTTL  time.Duration
	debounce    time.Duration
	queueSize   int
	esAPI       string // external-secrets.io API version path segment
}

func envStr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func envDur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
func envBool(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

func loadConfig() config {
	allow := map[string]bool{}
	for _, ns := range strings.Split(envStr("ALLOW_NAMESPACES", ""), ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			allow[ns] = true
		}
	}
	action := envStr("ACTION", "force-sync")
	if action != "force-sync" && action != "delete" {
		log.Fatalf("ACTION must be force-sync or delete, got %q", action)
	}
	return config{
		listenAddr: envStr("LISTEN_ADDR", ":9000"),
		action:     action,
		dryRun:     envBool("DRY_RUN", true),
		allowNS:    allow,
		storeName:  envStr("STORE_NAME", "openbao"),
		esCacheTTL: envDur("ES_CACHE_TTL", 15*time.Second),
		debounce:   envDur("DEBOUNCE", 2*time.Second),
		queueSize:  1 << 16,
		esAPI:      envStr("ESO_API_VERSION", "v1"),
	}
}

// ---------- audit event (only the fields we need) ----------

type auditEvent struct {
	Type    string          `json:"type"`
	Error   json.RawMessage `json:"error"`
	Request struct {
		Operation  string `json:"operation"`
		Path       string `json:"path"`
		MountPoint string `json:"mount_point"`
		MountType  string `json:"mount_type"`
	} `json:"request"`
}

func hasError(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null" && s != `""`
}

// relevantKey returns the ESO key for a successful KV (v2) secret write, else ok=false.
// e.g. path "secret/data/infra/tests/dummyapp", mount "secret/" -> "infra/tests/dummyapp"
func relevantKey(e *auditEvent) (string, bool) {
	if e.Type != "response" || hasError(e.Error) {
		return "", false
	}
	op := e.Request.Operation
	if op != "create" && op != "update" {
		return "", false
	}
	if e.Request.MountType != "kv" {
		return "", false
	}
	rel := strings.TrimPrefix(e.Request.Path, e.Request.MountPoint)
	if !strings.HasPrefix(rel, "data/") { // skip metadata/config/destroy/etc.
		return "", false
	}
	rel = strings.TrimPrefix(rel, "data/")
	if rel == "" {
		return "", false
	}
	return rel, true
}

// ---------- k8s client (in-cluster REST via ServiceAccount) ----------

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

type k8sClient struct {
	base    string
	http    *http.Client
	enabled bool
}

func newK8sClient() *k8sClient {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	caPEM, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil || host == "" {
		log.Printf("k8s: not in-cluster (%v) -> cluster actions DISABLED (dev mode, dry-run resolution skipped)", err)
		return &k8sClient{enabled: false}
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return &k8sClient{
		base:    fmt.Sprintf("https://%s:%s", host, port),
		enabled: true,
		http: &http.Client{
			Timeout:   8 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		},
	}
}

func (k *k8sClient) token() string {
	b, _ := os.ReadFile(saDir + "/token") // re-read each call: projected tokens rotate
	return strings.TrimSpace(string(b))
}

func (k *k8sClient) do(ctx context.Context, method, path, contentType string, body []byte) (int, []byte, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.base+path, r)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token())
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := k.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, rb, nil
}

// ---------- ExternalSecret index (key -> target Secrets), TTL-cached ----------

type esRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`   // ExternalSecret name
	Target    string `json:"target"` // target k8s Secret name
}

type esIndex struct {
	mu      sync.RWMutex
	byKey   map[string][]esRef
	builtAt time.Time
}

type esListResp struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			SecretStoreRef struct {
				Name string `json:"name"`
			} `json:"secretStoreRef"`
			Target struct {
				Name string `json:"name"`
			} `json:"target"`
			Data []struct {
				RemoteRef struct {
					Key string `json:"key"`
				} `json:"remoteRef"`
			} `json:"data"`
			DataFrom []struct {
				Extract struct {
					Key string `json:"key"`
				} `json:"extract"`
			} `json:"dataFrom"`
		} `json:"spec"`
	} `json:"items"`
}

func (s *server) refreshIndex(ctx context.Context) error {
	if !s.k8s.enabled {
		return fmt.Errorf("cluster disabled")
	}
	path := "/apis/external-secrets.io/" + s.cfg.esAPI + "/externalsecrets"
	code, body, err := s.k8s.do(ctx, "GET", path, "", nil)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("list externalsecrets: HTTP %d: %s", code, truncate(body, 200))
	}
	var lr esListResp
	if err := json.Unmarshal(body, &lr); err != nil {
		return err
	}
	idx := map[string][]esRef{}
	for _, it := range lr.Items {
		if it.Spec.SecretStoreRef.Name != s.cfg.storeName {
			continue
		}
		target := it.Spec.Target.Name
		if target == "" {
			target = it.Metadata.Name
		}
		ref := esRef{Namespace: it.Metadata.Namespace, Name: it.Metadata.Name, Target: target}
		seen := map[string]bool{}
		add := func(key string) {
			if key == "" || seen[key] {
				return
			}
			seen[key] = true
			idx[key] = append(idx[key], ref)
		}
		for _, d := range it.Spec.Data {
			add(d.RemoteRef.Key)
		}
		for _, d := range it.Spec.DataFrom {
			add(d.Extract.Key)
		}
	}
	s.index.mu.Lock()
	s.index.byKey = idx
	s.index.builtAt = time.Now()
	s.index.mu.Unlock()
	log.Printf("index: refreshed, %d keys from store %q", len(idx), s.cfg.storeName)
	return nil
}

func (s *server) resolve(ctx context.Context, key string) []esRef {
	s.index.mu.RLock()
	stale := time.Since(s.index.builtAt) > s.cfg.esCacheTTL || s.index.byKey == nil
	s.index.mu.RUnlock()
	if stale {
		if err := s.refreshIndex(ctx); err != nil {
			log.Printf("index: refresh failed: %v", err)
		}
	}
	s.index.mu.RLock()
	defer s.index.mu.RUnlock()
	return s.index.byKey[key]
}

// ---------- actions ----------

func (s *server) forceSync(ctx context.Context, ref esRef) error {
	path := fmt.Sprintf("/apis/external-secrets.io/%s/namespaces/%s/externalsecrets/%s",
		s.cfg.esAPI, ref.Namespace, ref.Name)
	patch := fmt.Sprintf(`{"metadata":{"annotations":{"force-sync":%q}}}`,
		strconv.FormatInt(time.Now().UnixNano(), 10))
	code, body, err := s.k8s.do(ctx, "PATCH", path, "application/merge-patch+json", []byte(patch))
	if err != nil {
		return err
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("HTTP %d: %s", code, truncate(body, 200))
	}
	return nil
}

func (s *server) deleteSecret(ctx context.Context, ref esRef) error {
	path := fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", ref.Namespace, ref.Target)
	code, body, err := s.k8s.do(ctx, "DELETE", path, "", nil)
	if err != nil {
		return err
	}
	if code == 404 {
		return nil // already gone; ESO will (re)create
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("HTTP %d: %s", code, truncate(body, 200))
	}
	return nil
}

// ---------- server ----------

type decision struct {
	Time    string  `json:"time"`
	Key     string  `json:"key"`
	Action  string  `json:"action"`
	Refs    []esRef `json:"refs"`
	Result  string  `json:"result"`
	DryRun  bool    `json:"dry_run"`
}

type server struct {
	cfg   config
	k8s   *k8sClient
	queue chan string
	index esIndex

	// counters
	total, matched, droppedFilter, droppedQueue uint64
	actionsOK, actionsErr, dryLogged            uint64

	mu       sync.Mutex
	recent   []decision // ring buffer (newest last)
}

func (s *server) record(d decision) {
	s.mu.Lock()
	s.recent = append(s.recent, d)
	if len(s.recent) > 200 {
		s.recent = s.recent[len(s.recent)-200:]
	}
	s.mu.Unlock()
}

var okBody = []byte(`{"status":"ok"}`)

// hot path: parse + filter + enqueue, return 200 ASAP.
func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	atomic.AddUint64(&s.total, 1)
	var e auditEvent
	if json.Unmarshal(body, &e) == nil {
		if key, ok := relevantKey(&e); ok {
			select {
			case s.queue <- key:
				atomic.AddUint64(&s.matched, 1)
			default:
				atomic.AddUint64(&s.droppedQueue, 1) // backpressure: never block OpenBao
			}
		} else {
			atomic.AddUint64(&s.droppedFilter, 1)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(okBody)
}

// background worker: debounce duplicate keys, then process.
func (s *server) worker() {
	pending := map[string]time.Time{}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case key := <-s.queue:
			pending[key] = time.Now()
		case now := <-tick.C:
			for key, t := range pending {
				if now.Sub(t) >= s.cfg.debounce {
					delete(pending, key)
					s.process(key)
				}
			}
		}
	}
}

func (s *server) process(key string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	refs := s.resolve(ctx, key)
	if len(refs) == 0 {
		log.Printf("process: key=%q no matching ExternalSecret (store=%s)", key, s.cfg.storeName)
		s.record(decision{Time: nowStr(), Key: key, Action: s.cfg.action, Result: "no-match", DryRun: s.cfg.dryRun})
		return
	}
	for _, ref := range refs {
		allowed := len(s.cfg.allowNS) == 0 || s.cfg.allowNS[ref.Namespace]
		if s.cfg.dryRun || !allowed || !s.k8s.enabled {
			reason := "DRY_RUN"
			if !allowed {
				reason = "ns-not-allowlisted"
			} else if !s.k8s.enabled {
				reason = "cluster-disabled"
			}
			log.Printf("process: key=%q WOULD %s %s/%s (target=%s) [%s]",
				key, s.cfg.action, ref.Namespace, ref.Name, ref.Target, reason)
			atomic.AddUint64(&s.dryLogged, 1)
			s.record(decision{Time: nowStr(), Key: key, Action: "would-" + s.cfg.action, Refs: []esRef{ref}, Result: reason, DryRun: true})
			continue
		}
		var err error
		if s.cfg.action == "delete" {
			err = s.deleteSecret(ctx, ref)
		} else {
			err = s.forceSync(ctx, ref)
		}
		if err != nil {
			atomic.AddUint64(&s.actionsErr, 1)
			log.Printf("process: key=%q %s %s/%s FAILED: %v", key, s.cfg.action, ref.Namespace, ref.Name, err)
			s.record(decision{Time: nowStr(), Key: key, Action: s.cfg.action, Refs: []esRef{ref}, Result: "error: " + err.Error()})
		} else {
			atomic.AddUint64(&s.actionsOK, 1)
			log.Printf("process: key=%q %s %s/%s (target=%s) OK", key, s.cfg.action, ref.Namespace, ref.Name, ref.Target)
			s.record(decision{Time: nowStr(), Key: key, Action: s.cfg.action, Refs: []esRef{ref}, Result: "ok"})
		}
	}
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	recent := make([]decision, len(s.recent))
	copy(recent, s.recent)
	s.mu.Unlock()
	// newest first
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}
	out := map[string]any{
		"config": map[string]any{
			"action": s.cfg.action, "dry_run": s.cfg.dryRun,
			"allow_namespaces": keys(s.cfg.allowNS), "store": s.cfg.storeName,
			"cluster_enabled": s.k8s.enabled,
		},
		"counters": map[string]uint64{
			"total": atomic.LoadUint64(&s.total),
			"matched": atomic.LoadUint64(&s.matched),
			"dropped_filter": atomic.LoadUint64(&s.droppedFilter),
			"dropped_queue": atomic.LoadUint64(&s.droppedQueue),
			"actions_ok": atomic.LoadUint64(&s.actionsOK),
			"actions_err": atomic.LoadUint64(&s.actionsErr),
			"dry_logged": atomic.LoadUint64(&s.dryLogged),
		},
		"recent": recent,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		resp, err := http.Get("http://127.0.0.1" + envStr("LISTEN_ADDR", ":9000") + "/healthz")
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	cfg := loadConfig()
	s := &server{cfg: cfg, k8s: newK8sClient(), queue: make(chan string, cfg.queueSize)}
	go s.worker()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			s.handleAudit(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(dashboardHTML))
	})

	log.Printf("audit-resync up on %s | action=%s dry_run=%v allow_ns=%v store=%s cluster=%v",
		cfg.listenAddr, cfg.action, cfg.dryRun, keys(cfg.allowNS), cfg.storeName, s.k8s.enabled)
	log.Fatal(http.ListenAndServe(cfg.listenAddr, mux))
}

// ---------- helpers ----------

func nowStr() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func keys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}
func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n])
	}
	return string(b)
}

const dashboardHTML = `<!doctype html><html><head><meta charset="utf-8">
<title>audit-resync</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{color-scheme:dark}body{margin:0;font:14px system-ui,sans-serif;background:#0e1116;color:#e6edf3}
header{padding:16px 20px;border-bottom:1px solid #232a33;background:#11161d}
h1{margin:0;font-size:16px}.sub{color:#8b949e;font-size:12px;margin-top:4px}
main{padding:18px 20px;max-width:1100px;margin:0 auto}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}
.card{border:1px solid #232a33;border-radius:8px;padding:10px 14px;background:#161b22;min-width:110px}
.card .n{font-size:22px;font-weight:700}.card .l{color:#8b949e;font-size:11px;text-transform:uppercase}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #232a33;font-size:13px}
th{color:#8b949e;font-size:11px;text-transform:uppercase}
.ok{color:#4ade80}.err{color:#f87171}.dry{color:#fbbf24}
code{font-family:ui-monospace,Menlo,monospace;color:#79c0ff}
.cfg{font-size:12px;color:#8b949e;margin-bottom:10px}
</style></head><body>
<header><h1>audit-resync controller</h1><div class="sub">OpenBao audit &rarr; ESO resync &rarr; Reloader &middot; auto-refresh 2s &middot; <span id="ts">…</span></div></header>
<main>
<div class="cfg" id="cfg"></div>
<div class="cards" id="cards"></div>
<table><thead><tr><th>Time</th><th>Key</th><th>Action</th><th>Target</th><th>Result</th></tr></thead><tbody id="rows"></tbody></table>
</main>
<script>
const esc=s=>String(s??"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
async function r(){try{const d=await(await fetch("/status")).json();
const c=d.config;document.getElementById("cfg").innerHTML=
"action=<code>"+esc(c.action)+"</code> &middot; dry_run=<code>"+c.dry_run+"</code> &middot; allow_ns=<code>"+esc((c.allow_namespaces||[]).join(",")||"(all)")+"</code> &middot; store=<code>"+esc(c.store)+"</code> &middot; cluster=<code>"+c.cluster_enabled+"</code>";
const k=d.counters;document.getElementById("cards").innerHTML=Object.entries(k).map(([n,v])=>
'<div class="card"><div class="n">'+v+'</div><div class="l">'+esc(n)+'</div></div>').join("");
document.getElementById("rows").innerHTML=(d.recent||[]).map(x=>{
const cls=x.result==="ok"?"ok":(x.dry_run?"dry":(x.result&&x.result.startsWith("error")?"err":""));
const tgt=(x.refs||[]).map(rr=>rr.namespace+"/"+rr.target).join(", ")||"—";
return "<tr><td>"+esc(x.time)+"</td><td><code>"+esc(x.key)+"</code></td><td>"+esc(x.action)+"</td><td><code>"+esc(tgt)+"</code></td><td class='"+cls+"'>"+esc(x.result)+"</td></tr>";
}).join("");
document.getElementById("ts").textContent="updated "+new Date().toLocaleTimeString();
}catch(e){document.getElementById("ts").textContent="unreachable";}}
r();setInterval(r,2000);
</script></body></html>`
