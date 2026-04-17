# SecureFlow Vulnerability Index

This index mirrors Section 7 of the project brief. Every ID listed here is real
and planted in this repository. Your deliverable is a pipeline that detects
every ID, followed by remediations that resolve them.

---

## Auth Service — `services/auth-service/app.py`

| ID    | Vulnerability                          | Location |
|-------|----------------------------------------|----------|
| AV-01 | SQL Injection on `/login`              | `app.py` login() — string-concatenated query |
| AV-02 | SQL Injection on `/register`           | `app.py` register() — string-interpolated INSERT |
| AV-03 | Broken auth — JWT forgery              | Hardcoded `SECRET_KEY` enables token forgery |
| AV-04 | Brute force — no rate limiting         | `/login` has no lockout, CAPTCHA, or throttle |
| AV-05 | Insecure password storage              | `hash_password()` — MD5, no salt |
| AV-06 | Admin panel — no authorisation check   | `/admin` does not verify `role == 'admin'` |
| AV-07 | Hardcoded JWT secret                   | `SECRET_KEY = 'redacted'` fallback |
| AV-08 | Sensitive data in error responses      | Exceptions return query string + stack to client |

## Transaction Service — `services/transaction-service/app.py`

| ID    | Vulnerability                          | Location |
|-------|----------------------------------------|----------|
| TV-01 | IDOR — account balance                 | `GET /balance/<account_id>` — no ownership check |
| TV-02 | IDOR — transaction history             | `GET /transactions/<account_id>` |
| TV-03 | Negative transfer amount               | `POST /transfer` — no `amount > 0` check |
| TV-04 | Mass assignment — virtual card         | `POST /cards` — splats entire JSON into INSERT |
| TV-05 | Business logic — balance overflow      | `/transfer` — no max / balance check |
| TV-06 | Missing CSRF protection                | State-changing endpoints accept no CSRF token |
| TV-07 | Unauthenticated transfer (expired JWT) | `/verify` in auth-service calls `verify_exp=False` |

## Frontend — `services/frontend/app.py`

| ID    | Vulnerability                          | Location |
|-------|----------------------------------------|----------|
| FV-01 | Reflected XSS                          | `/dashboard?msg=...` — autoescape disabled |
| FV-02 | Stored XSS — transaction notes         | Notes field rendered unescaped in dashboard |
| FV-03 | Session hijacking                      | `SESSION_SECRET='redacted'` in docker-compose.yml |
| FV-04 | (not included in this engagement)      | — |
| FV-05 | CSRF — transfer and login forms        | No CSRF token in any form |
| FV-06 | Clickjacking                           | No X-Frame-Options / CSP frame-ancestors |
| FV-07 | Missing security headers               | No CSP, HSTS, X-Content-Type-Options, Referrer-Policy |

## Infrastructure — compose and Terraform

| ID    | Vulnerability                          | Location |
|-------|----------------------------------------|----------|
| IV-01 | Hardcoded DB password                  | `docker-compose.yml` POSTGRES_PASSWORD |
| IV-02 | Database exposed on host network       | `docker-compose.yml` ports 5432 and 5433 |
| IV-03 | Secrets in environment variables       | `docker-compose.yml` SECRET_KEY, SESSION_SECRET, DB_PASSWORD |
| IV-04 | Secrets in committed `.env` file       | `.env` — AWS keys, JWT secret, Sonar token, DB password |
| IV-05 | Containers running as root             | All three Dockerfiles — no USER directive |
| IV-06 | No resource limits                     | `docker-compose.yml` — no `deploy.resources` block |
| IV-07 | No network segmentation                | `docker-compose.yml` — all services on default bridge |
| IV-08 | Overly permissive IAM                  | `infra/terraform/modules/iam/main.tf` — AdministratorAccess, wildcard actions |
| IV-09 | Unencrypted S3 buckets                 | `infra/terraform/modules/s3/main.tf` — no SSE, public access blocks off |
| IV-10 | EKS nodes in public subnets            | `infra/terraform/modules/eks/main.tf` + `modules/vpc/main.tf` — public subnets, public IPs, public API endpoint |

## Container and Kubernetes — Dockerfiles and `infra/kubernetes/base/`

| ID    | Vulnerability                          | Location |
|-------|----------------------------------------|----------|
| CK-01 | Vulnerable base image                  | All Dockerfiles use `python:3.9-slim` |
| CK-02 | No non-root user                       | No USER directive in any Dockerfile |
| CK-03 | Unpinned image tags                    | `docker-compose.yml` and K8s base use `redacted:14`, `:latest` |
| CK-04 | Privileged containers                  | `infra/kubernetes/base/*-service.yaml` — `privileged: true` |
| CK-05 | No resource limits                     | K8s base deployments — no `resources:` block |
| CK-06 | `:latest` image tag                    | K8s base uses `image: secureflow/*:latest` |
| CK-07 | Missing required labels                | K8s base deployments — no `app` or `team` labels |
| CK-08 | No NetworkPolicy                       | Namespace has no `NetworkPolicy` resources |
| CK-09 | Secrets in ConfigMaps                  | `infra/kubernetes/base/configmap.yaml` — JWT + DB passwords |

---

## Detection Mapping

Each scanning tool in the brief's Section 6 stack should find a specific
subset of these IDs. Cross-check your pipeline output against this table —
if a scanner is not catching its expected findings, the scanner is
misconfigured.

| Tool             | Should detect |
|------------------|---------------|
| Gitleaks         | IV-03, IV-04 (all five committed secrets) |
| SonarQube SAST   | AV-01, AV-02, AV-07, AV-08, TV-03, TV-04 |
| Trivy (image)    | CK-01 |
| Trivy (K8s)      | CK-04, CK-05, CK-06, CK-07, CK-09 |
| Checkov          | IV-08, IV-09, IV-10 |
| OPA Gatekeeper   | CK-04, CK-05, CK-06, CK-07 (at admission) |
| Falco            | runtime behaviour following any successful exploit of AV-*, TV-*, FV-* |
| OWASP ZAP (DAST) | AV-01 at HTTP level, FV-01, FV-02, FV-06, FV-07 |
