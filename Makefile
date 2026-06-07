# Validation lab controls. The lab is local-only and torn down on demand.
COMPOSE = docker compose -f lab/docker-compose.yml

.PHONY: lab-up lab-down lab-status lab-logs benchmark

lab-up:        ## Start the isolated vulnerable-target lab (localhost-only).
	$(COMPOSE) up -d
	@echo "Lab starting. Targets (127.0.0.1 only):"
	@echo "  Juice Shop  http://127.0.0.1:3000"
	@echo "  DVWA        http://127.0.0.1:8081   (login admin/password, set DVWA Security)"
	@echo "  DVGA        http://127.0.0.1:5013"
	@echo "  SSRF lab    http://127.0.0.1:8300"
	@echo "  Mock IMDS   http://127.0.0.1:8200   (FAKE creds only)"
	@echo "Run 'make lab-status' to confirm reachability."

lab-down:      ## Stop and remove the lab (and its volumes).
	$(COMPOSE) down -v

lab-status:    ## Show container status + reachability of each target.
	@$(COMPOSE) ps
	@echo "--- reachability (localhost only) ---"
	@for p in 3000 8081 5013 8300 8200; do \
	  printf "  127.0.0.1:%s -> " $$p; \
	  curl -s -o /dev/null -w "HTTP %{http_code}\n" --max-time 5 http://127.0.0.1:$$p/ || echo "unreachable"; \
	done

lab-logs:      ## Tail lab logs.
	$(COMPOSE) logs -f

benchmark:     ## Run the validation benchmark against the lab and print metrics.
	.venv/bin/bbp benchmark validation/lab_profile.docker.yml
