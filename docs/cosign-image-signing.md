# Cosign Image Signing

The security gate signs images only after the `security-gate` job passes. The workflow uses a self-managed Cosign keypair stored in GitHub Actions configuration.

## Generate the Keypair

Run this once from a trusted workstation:

```bash
export COSIGN_PASSWORD="$(openssl rand -base64 32)"
cosign generate-key-pair
```

Cosign writes:

* `cosign.key` - encrypted private key.
* `cosign.pub` - public verification key.

## Store GitHub Configuration

Store the private key and password as GitHub Actions secrets:

```bash
gh secret set COSIGN_PRIVATE_KEY < cosign.key
gh secret set COSIGN_PASSWORD --body "$COSIGN_PASSWORD"
```

Store the public key as a GitHub Actions repository variable:

```bash
gh variable set COSIGN_PUBLIC_KEY --body "$(cat cosign.pub)"
```

After confirming the secrets and variable exist, remove the local key files from the workstation:

```bash
rm cosign.key cosign.pub
unset COSIGN_PASSWORD
```

## Pipeline Behavior

The `Sign and Verify Images` job in `.github/workflows/security-gate-pipeline.yml` runs only when:

* The workflow is not running for a pull request.
* The `security-gate` job succeeds.

The job builds, pushes, signs, generates SPDX SBOMs, attaches SBOM attestations, and verifies these images:

* `auth-service`
* `frontend`
* `transaction-service`

Images are pushed to GitHub Container Registry using this format:

```text
ghcr.io/<repository-owner>/<repository-name>-<service>:<commit-sha>
```

Each pushed image tag is resolved to its immutable registry digest before signing:

```bash
digest="$(docker buildx imagetools inspect "$image" | awk '/Digest:/ {print $2; exit}')"
image_digest="${image%@*}@${digest}"
```

Each digest reference is signed with:

```bash
cosign sign --yes --key env://COSIGN_PRIVATE_KEY "$image_digest"
```

Each digest signature is verified with:

```bash
cosign verify --key cosign.pub "$image_digest"
```

## SBOM Attestation

For each signed image digest, Trivy generates an SPDX JSON SBOM:

```bash
trivy image --format spdx-json --output "$sbom_file" "$image_digest"
```

The SBOM is attached to the image digest as a Cosign in-toto attestation:

```bash
cosign attest --yes \
  --key env://COSIGN_PRIVATE_KEY \
  --type spdx \
  --predicate "$sbom_file" \
  "$image_digest"
```

The pipeline verifies the attached SBOM attestation with the public key:

```bash
cosign verify-attestation --key cosign.pub --type spdx "$image_digest"
```

The workflow also uploads the generated SBOM files and attestation verification output as the `signed-image-sboms` artifact.
