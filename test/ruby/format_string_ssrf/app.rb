# `"tmpl %s" % value` is Ruby's printf-style format. Mapping `%` to BIN_OP_REM is
# what lets internal/analysis/ssrf.go read operand 0 as a TEMPLATE and render the
# placeholder as a dynamic marker -- here in the HOST position, so the host is
# attacker-controlled and this is a real SSRF.
#
# The host placeholder is the point. Mapping `%` to BIN_OP_ADD instead makes
# constSkeleton concatenate the raw template with the tainted value, yielding the
# prefix "https://%s.internal.example.com/status" -- which LOOKS host-fixed, so
# hostFixed() wrongly suppresses a real finding. A path-position placeholder is
# suppressed under either mapping and would not discriminate.
def fetch(params)
  url = "https://%s.internal.example.com/status" % params[:tenant]
  Net::HTTP.get(url)
end
