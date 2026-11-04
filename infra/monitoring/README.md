# SIEVE monitoring starter

This directory contains a Prometheus scrape configuration, starter alert rules, and a Grafana dashboard for the API metrics endpoint.

1. Set `METRICS_BEARER_TOKEN` in the API secret store to a unique value of at least 32 characters.
2. Put the same token, without the `Bearer ` prefix, in Prometheus's protected `sieve-metrics-token` secret file.
3. Replace `api.example.invalid:443` with the API's HTTPS hostname and load `prometheus.yml` and `alerts.yml` into Prometheus.
4. Import `sieve-dashboard.json` into Grafana and select the Prometheus data source.
5. Route Prometheus alerts through the deployment's configured Alertmanager receiver and verify that responders receive them.

The 5% server-error threshold, ten-minute window, and minimum request volume are starting values, not agreed service targets. Tune them against staging traffic and an explicitly agreed service-level objective before production use. The dashboard does not imply that a provider is operational unless provider connectivity checks have been implemented; inspect the API readiness response for current integration status.
