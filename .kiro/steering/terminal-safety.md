---
inclusion: always
---

# Terminal Safety Rules

## CRITICAL: Prevent Terminal Crashes

**NEVER send large amounts of text to the terminal in a single command.** This will cause the terminal to crash or freeze.

### Rules for Terminal Commands:

1. **Avoid commands that output large amounts of text** such as:
   - `cat` on large files
   - `echo` with very long strings
   - Commands that print entire file contents
   - Recursive listings without depth limits

2. **Use file tools instead of terminal commands** for:
   - Reading file contents → Use `readFile` or `readMultipleFiles`
   - Searching in files → Use `grepSearch`
   - Finding files → Use `fileSearch`
   - Writing files → Use `fsWrite` or `strReplace`

3. **When terminal commands are necessary:**
   - Limit output with `head`, `tail`, or `grep`
   - Use pagination or filtering
   - Redirect large outputs to files instead of stdout

4. **Safe alternatives:**
   - ❌ `cat large-file.txt`
   - ✅ `readFile` tool
   - ❌ `find . -type f`
   - ✅ `fileSearch` tool
   - ❌ `grep -r "pattern" .`
   - ✅ `grepSearch` tool

### Examples of Safe Commands:

```bash
# Good - limited output
ls -la
head -n 20 file.txt
tail -n 50 log.txt
grep "error" file.txt | head -n 10

# Bad - potentially large output
cat large-file.txt
find . -type f
grep -r "pattern" .
```

**Remember: Always prefer Kiro's file tools over terminal commands for file operations.**
