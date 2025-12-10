# ----------------- Firewalld Configuration ----------------- #

if command -v firewall-cmd >/dev/null 2>&1; then
  log "Configuring Firewalld..."

  FIREWALLD_SERVICE="/etc/firewalld/services/SSHCustom.xml"
  FIREWALLD_ZONE="/etc/firewalld/zones/public.xml"

  # Ensure Firewalld config directories exist
  mkdir -p /etc/firewalld/services /etc/firewalld/zones

  # Back up existing files if present
  backup "$FIREWALLD_SERVICE"
  backup "$FIREWALLD_ZONE"

  # Create / update custom SSH service definition
  cat > "$FIREWALLD_SERVICE" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>SSHCustom</short>
  <description>Custom SSH port for hardened access</description>
  <port port="$CUSTOM_SSH_PORT" protocol="tcp"/>
</service>
EOF

  # If the public zone file does not exist, create a minimal one
  if [[ ! -f "$FIREWALLD_ZONE" ]]; then
    cat > "$FIREWALLD_ZONE" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>public</short>
  <description>Public Zone</description>
  <target>default</target>
</zone>
EOF
    log "Created minimal Firewalld public zone config at $FIREWALLD_ZONE"
  fi

  # Inject rules for the custom SSH port into the public zone if not already present
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

  # Reload Firewalld to apply zone + service changes
  if firewall-cmd --reload; then
    log "Firewalld reloaded successfully."
  else
    log "WARNING: Failed to reload Firewalld after updating configs."
  fi

  # Also add the port via firewall-cmd (permanent) for good measure
  if firewall-cmd --permanent --zone=public --add-port=${CUSTOM_SSH_PORT}/tcp; then
    firewall-cmd --reload || true
  else
    log "WARNING: firewall-cmd --add-port ${CUSTOM_SSH_PORT}/tcp failed."
  fi

  # Final verification
  if firewall-cmd --list-ports | grep -q "${CUSTOM_SSH_PORT}/tcp"; then
    log "Custom SSH port ${CUSTOM_SSH_PORT} is active in Firewalld."
  else
    log "WARNING: Custom SSH port ${CUSTOM_SSH_PORT} does not appear in Firewalld port list."
  fi
else
  log "firewalld not installed; skipping Firewalld configuration."
fi
