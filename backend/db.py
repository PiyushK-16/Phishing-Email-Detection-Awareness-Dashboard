"""SQLite storage. Stores metadata only - NEVER the email body (privacy by default)."""
import os, sqlite3
from contextlib import closing
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses(
  analysis_id INTEGER PRIMARY KEY AUTOINCREMENT, sender_domain TEXT, subject TEXT,
  risk_score INTEGER, classification TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS indicators(
  indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id INTEGER REFERENCES analyses(analysis_id) ON DELETE CASCADE,
  indicator_type TEXT, description TEXT, severity TEXT);
CREATE TABLE IF NOT EXISTS url_analyses(
  url_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id INTEGER REFERENCES analyses(analysis_id) ON DELETE CASCADE,
  url_safe_representation TEXT, risk_score INTEGER, findings TEXT);
CREATE TABLE IF NOT EXISTS users(  -- optional, unused until auth is added
  user_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, role TEXT);
"""


def db_path():
    return os.getenv("DB_PATH", "phishing_history.db")


def get_conn():
    c = sqlite3.connect(db_path()); c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON"); return c


def init_db():
    with closing(get_conn()) as c, c:
        c.executescript(SCHEMA)


def save_analysis(result, sender_domain, subject):
    with closing(get_conn()) as c, c:
        aid = c.execute("INSERT INTO analyses(sender_domain,subject,risk_score,classification,created_at) VALUES(?,?,?,?,?)",
                        (sender_domain, subject[:300], result["risk_score"], result["classification"],
                         datetime.now(timezone.utc).isoformat(timespec="seconds"))).lastrowid
        rows = [(aid, i["type"], i["description"], i["severity"]) for i in result["indicators"]]
        rows += [(aid, "keyword", k, "low") for k in result["keywords"]]
        c.executemany("INSERT INTO indicators(analysis_id,indicator_type,description,severity) VALUES(?,?,?,?)", rows)
        c.executemany("INSERT INTO url_analyses(analysis_id,url_safe_representation,risk_score,findings) VALUES(?,?,?,?)",
                      [(aid, u["url"], u["score"], "; ".join(u["findings"])) for u in result["url_analyses"]])
    return aid


def list_analyses(q="", classification="", sort="created_at", order="desc", limit=200):
    sort = sort if sort in ("created_at", "risk_score") else "created_at"
    order = "ASC" if order.lower() == "asc" else "DESC"
    sql, args = "SELECT * FROM analyses WHERE 1=1", []
    if q:
        sql += " AND (subject LIKE ? OR sender_domain LIKE ?)"; args += [f"%{q}%"] * 2
    if classification:
        sql += " AND classification = ?"; args.append(classification)
    sql += f" ORDER BY {sort} {order}, analysis_id DESC LIMIT ?"; args.append(min(int(limit), 500))
    with closing(get_conn()) as c:
        return [dict(r) for r in c.execute(sql, args)]


def get_analysis(aid):
    with closing(get_conn()) as c:
        a = c.execute("SELECT * FROM analyses WHERE analysis_id=?", (aid,)).fetchone()
        if not a:
            return None
        d = dict(a)
        d["indicators"] = [dict(r) for r in c.execute("SELECT indicator_type,description,severity FROM indicators WHERE analysis_id=?", (aid,))]
        d["url_analyses"] = [dict(r) for r in c.execute("SELECT url_safe_representation,risk_score,findings FROM url_analyses WHERE analysis_id=?", (aid,))]
        return d


def delete_analysis(aid):
    with closing(get_conn()) as c, c:
        return c.execute("DELETE FROM analyses WHERE analysis_id=?", (aid,)).rowcount > 0


def stats():
    with closing(get_conn()) as c:
        total = c.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        avg = c.execute("SELECT COALESCE(AVG(risk_score),0) FROM analyses").fetchone()[0]
        by_class = {r[0]: r[1] for r in c.execute("SELECT classification, COUNT(*) FROM analyses GROUP BY classification")}
        flagged = c.execute("SELECT COUNT(*) FROM analyses WHERE risk_score>40").fetchone()[0]
        hist = [0] * 5
        for (s,) in c.execute("SELECT risk_score FROM analyses"):
            hist[min(s // 20, 4)] += 1
        trend = [dict(r) for r in c.execute(
            "SELECT substr(created_at,1,10) day, COUNT(*) count, ROUND(AVG(risk_score),1) avg FROM analyses GROUP BY day ORDER BY day")]
    return {"total": total, "avg_score": round(avg, 1), "by_class": by_class,
            "flagged": {"flagged": flagged, "not_flagged": total - flagged},
            "histogram": [{"bucket": f"{i*20}-{i*20+19 if i<4 else 100}", "count": hist[i]} for i in range(5)], "trend": trend}


def top_indicators(limit=8):
    with closing(get_conn()) as c:
        ind = [dict(r) for r in c.execute("SELECT description, COUNT(*) count FROM indicators WHERE indicator_type!='keyword' GROUP BY description ORDER BY count DESC LIMIT ?", (limit,))]
        kw = [dict(r) for r in c.execute("SELECT description keyword, COUNT(*) count FROM indicators WHERE indicator_type='keyword' GROUP BY description ORDER BY count DESC LIMIT ?", (limit,))]
    return {"indicators": ind, "keywords": kw}
