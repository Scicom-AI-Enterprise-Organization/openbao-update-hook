# Declarative audit device configuration (audit devices can't be enabled via API).
# Points the dev OpenBao at the audit-resync controller in this compose stack.
audit "http" "http" {
  description = "HTTP audit device -> audit-resync controller"
  options {
    uri = "http://controller:9000"
  }
}
