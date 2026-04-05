# Nuclei Optimization for allocine.fr

## Problem
The original Nuclei configuration was timing out after 15 minutes with no results on allocine.fr due to:
- Too many tags (exposure,config,api,swagger,openapi,graphql,auth,jwt,files,paths)
- Slow timeout settings (12s per request)
- Too many retries (2)
- Low rate limit (50 req/s)
- Low concurrency (10)

## Solution
Optimized Nuclei configuration for **fast API endpoint discovery**:

### Tag Optimization
**Before:**
```
-tags exposure,config,api,swagger,openapi,graphql,auth,jwt,files,paths
-etags dos,intrusive,headless,cve,fuzz
```

**After:**
```
-tags exposure,api,swagger,openapi
-etags dos,intrusive,headless,cve,fuzz,fuzzing,brute-force
```

**Rationale:**
- Removed slow/noisy tags: `config`, `graphql`, `auth`, `jwt`, `files`, `paths`
- Kept only fast API discovery tags: `exposure`, `api`, `swagger`, `openapi`
- Added more exclusions: `fuzzing`, `brute-force`

### Performance Parameters
**Before:**
```python
NUCLEI_REQUEST_TIMEOUT_SECONDS = 12
NUCLEI_RETRIES = 2
NUCLEI_RATE_LIMIT = 50
NUCLEI_CONCURRENCY = 10
```

**After:**
```python
NUCLEI_REQUEST_TIMEOUT_SECONDS = 8
NUCLEI_RETRIES = 1
NUCLEI_RATE_LIMIT = 100
NUCLEI_CONCURRENCY = 20
```

**Rationale:**
- Faster timeout (8s vs 12s) = 33% faster per request
- Fewer retries (1 vs 2) = less time wasted on dead endpoints
- Higher rate limit (100 vs 50) = 2x throughput
- More concurrency (20 vs 10) = 2x parallel execution

### Expected Results
- **Scan time:** ~2-5 minutes (vs 15+ minutes timeout)
- **Template count:** ~50-100 templates (vs 500+ templates)
- **Focus:** API endpoint discovery only (swagger, openapi, exposed APIs)
- **Trade-off:** Less comprehensive coverage, but much faster and more reliable

### Testing Results
Manual testing on allocine.fr showed:
```bash
# Single target test (www.allocine.fr)
nuclei -u https://www.allocine.fr -tags exposure,api,swagger,openapi \
  -timeout 8 -rate-limit 100 -c 20 -silent

# Result: Completed in ~30 seconds with no findings
# (Expected - allocine.fr has no exposed API docs)
```

### Preset Command Update
**Recon Fast preset:**
```bash
{nuclei_path} -list {targets_file} \
  -tags exposure,api,swagger,openapi \
  -etags dos,intrusive,headless,cve,fuzz,fuzzing,brute-force \
  -timeout 8 -retries 1 -rate-limit 100 -c 20 \
  -bs 8 -mhe 8 -ss host-spray -no-httpx -project -silent \
  -header "X-Forwarded-For: 127.0.0.1" \
  -jsonl-export {json_file}
```

## Usage
The optimized configuration is now the default. Users can:
1. Use default mode (optimized for speed)
2. Use "Recon Fast" preset (same optimization)
3. Create custom commands for deeper scans if needed

## When to Use Custom Commands
For comprehensive security testing (not just endpoint discovery), users can enable custom commands with:
```bash
# Full security scan (slower but comprehensive)
{nuclei_path} -list {targets_file} \
  -tags exposure,config,api,swagger,openapi,graphql,auth,jwt,panel,debug,backup,logs \
  -severity critical,high,medium \
  -timeout 15 -retries 2 -rate-limit 30 -c 10 \
  -jsonl-export {json_file}
```

## Monitoring
The tool now shows:
- `[*] Tags: exposure,api,swagger,openapi (optimized for speed)`
- Faster progress updates (every 30s)
- Clearer timeout messages
- Better error handling for partial results
