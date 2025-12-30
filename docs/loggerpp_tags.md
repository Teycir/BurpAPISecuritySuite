# Logger++ Tags for BurpAPISecuritySuite

## Tested & Working Tags

### 1. API Endpoint Detection ✓
```
Tag: api_endpoint
Filter: Request.Path CONTAINS "/api/" OR Request.Path CONTAINS "/v1/" OR Request.Path CONTAINS "/v2/" OR Request.Path CONTAINS "/graphql" OR Response.Headers CONTAINS "application/json"
Color: Blue
```

### 2. Authentication Endpoints ✓
```
Tag: auth
Filter: Request.Path CONTAINS "/auth" OR Request.Path CONTAINS "/login" OR Request.Path CONTAINS "/token" OR Request.Headers CONTAINS "Authorization"
Color: Purple
```

### 3. IDOR/BOLA Candidates ✓
```
Tag: idor_risk
Filter: Request.Path MATCHES ".*/[0-9]+$" OR Request.Path MATCHES ".*/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" OR Request.Path MATCHES ".*/[0-9a-f]{24}$"
Color: Red
```

### 4. Sensitive Data Exposure ✓
```
Tag: sensitive
Filter: Response.Body CONTAINS "password" OR Response.Body CONTAINS "token" OR Response.Body CONTAINS "secret" OR Response.Body CONTAINS "api_key" OR Response.Body CONTAINS "credit"
Color: Orange
```

### 5. Write Operations ✓
```
Tag: write_ops
Filter: Request.Method == "POST" OR Request.Method == "PUT" OR Request.Method == "PATCH" OR Request.Method == "DELETE"
Color: Green
```

### 7. JWT Detection ✓
```
Tag: jwt
Filter: Request.Headers CONTAINS "Bearer" OR Request.Cookies MATCHES ".*eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+.*"
Color: Cyan
```

### 8. Admin/Debug Endpoints ✓
```
Tag: admin_debug
Filter: Request.Path CONTAINS "/admin" OR Request.Path CONTAINS "/debug" OR Request.Path CONTAINS "/test" OR Request.Path CONTAINS "/.env" OR Request.Path CONTAINS "/swagger"
Color: Magenta
```

### 9. Reflected Parameters (XSS Risk) ⚠️
```
Tag: reflected
Filter: Response.Body CONTAINS Request.Query
Color: Pink
Note: CPU-intensive on large datasets
```

### 10. Unauthenticated API Calls (FIXED)
```
Tag: no_auth
Filter: Request.Path CONTAINS "/api/" AND NOT Request.Headers CONTAINS "Authorization"
Color: Gray
```

## Performance Tips

**⚠️ Burp can freeze when applying complex filters to large datasets**

1. **Clear Logger++ history first** (right-click → Clear)
2. **Apply simple tags first** (tags 1-2) before complex regex (tag 3)
3. **Disable auto-logging** while creating tags
4. **Test on small dataset** before full capture
5. **Avoid Response.Body filters** on 10K+ rows (tags 4, 9)

## Syntax Notes

- Use `OR` not `||`
- Use `AND` not `&&`
- Use `NOT` not `!`
- `Request.Method == "POST"` (not `Method`)
- REGEX tags (tag 3) are CPU-intensive

## Export to BurpAPISecuritySuite

1. Apply filter in Logger++
2. Select matching rows → Export
3. BurpAPISecuritySuite → Import button → Run Fuzzer
