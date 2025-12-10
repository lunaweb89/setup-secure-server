# ----------------- Firewalld Configuration (dedicated only) ----------------- #

# Only touch firewalld if:
#  - firewall-cmd exists, AND
#  - we are NOT in a virtualized environment (likely dedicated server)
if ! command -v firewall-cmd >/dev/null 2>&1; then
  log "firewalld not installed; skipping Firewalld configuration."
else
  # Detect virtualization (VPS, cloud, etc.)
  VIRT_TYPE="$(systemd-detect-virt || true)"
  if [[ -n "$VIRT_TYPE" && "$VIRT_TYPE" != "none" ]]; then
    log "Virtualized environment detected ($VIRT_TYPE) — skipping Firewalld, using UFW only."
  else
    log "Configuring Firewalld on (likely) dedicated server..."

    FIREWALLD_SERVICE="/etc/firewalld/services/SSHCustom.xml"
    FIREWALLD_ZONE="/etc/firewalld/zones/public.xml"

    mkdir -p "/etc/firewalld/services" "/etc/firewalld/zones"

    # Backup existing files if they exist
    backup "$FIREWALLD_SERVICE"
    backup "$FIREWALLD_ZONE"

    # (Re)create SSHCustom.xml for the custom SSH port
    cat > "$FIREWALLD_SERVICE" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>SSHCustom</short>
  <description>Custom SSH port</description>
  <port port="$CUSTOM_SSH_PORT" protocol="tcp"/>
</service>
EOF

    # If zone file does not exist, create a minimal public zone
    if [[ ! -f "$FIREWALLD_ZONE" ]]; then
      cat > "$FIREWALLD_ZONE" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>public</short>
  <description>Public Zone</description>
</zone>
EOF
      log "Created minimal Firewalld public zone config."
    fi

    # Make sure the custom port is present in the public zone file
    if ! grep -q "port=\"$CUSTOM_SSH_PORT\"" "$FIREWALLD_ZONE"; then
      sed -i "/<\/zone>/i \
  <rule family=\"ipv4\">\n\
    <source address=\"0.0.0.0/0\"/>\n\
    <port port=\"$CUSTOM_SSH_PORT\" protocol=\"tcp\"/>\n\
    <accept/>\n\
  </rule>\n\
  <rule family=\"ipv6\">\n\
    <source address=\"::/0\"/>\n\
    <port port=\"$CUSTOM_SSH_PORT\" protocol=\"tcp\"/>\n\
    <accept/>\n\
  </rule>" "$FIREWALLD_ZONE"
      log "Custom port $CUSTOM_SSH_PORT rules injected into Firewalld public zone."
    else
      log "Custom port $CUSTOM_SSH_PORT already present in Firewalld public zone."
    fi

    # Apply changes
    if firewall-cmd --reload; then
      log "Firewalld reloaded successfully."
      STEP_ufw_firewall="${STEP_ufw_firewall:-OK}"  # don't mark fail just because of Firewalld
    else
      log "WARNING: firewall-cmd --reload failed. Check Firewalld configuration."
    fi
  fi
fi
