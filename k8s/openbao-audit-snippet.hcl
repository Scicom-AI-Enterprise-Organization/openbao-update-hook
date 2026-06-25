# Add this stanza to the IN-CLUSTER OpenBao server config (the same place its
# existing listener/storage stanzas live — Helm `server.config` / the OpenBao
# ConfigMap). Then restart or SIGHUP the OpenBao pods so it loads.
#
# Audit devices are declarative-only (cannot be enabled via the /sys/audit API).
#
# !!! READ BEFORE APPLYING — OpenBao audit is fail-closed !!!
#   - BOOT: every declared audit device must pass a test POST at startup. If the
#     audit-resync Service is not reachable when OpenBao boots, OpenBao will
#     CRASH-LOOP. => Deploy audit-resync (Ready, 2 replicas) BEFORE adding this.
#   - RUNTIME: a request succeeds only if at least ONE audit device logs it. KEEP
#     your existing primary audit device (file/socket) so a controller blip never
#     blocks OpenBao. This http device should be an ADDITIONAL device, not the only one.

audit "http" "resync" {
  description = "audit-resync controller -> ESO resync trigger"
  options {
    uri = "http://audit-resync.openbao.svc:9000"
  }
}
