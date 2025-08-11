# Tesco Shift Collector (Archived)

🛠️ **Open-source robot for the old Tesco eShift booking system**  
📬 Automatically clicked shift links as soon as they arrived via email  
⚠️ **This project is archived** – eShift is no longer used anywhere

## ⚡ What was this?

This tool was built for Tesco part-time workers using the now-retired **eShift** system.  
In short: when eShift sent new shifts via email, this bot immediately clicked the links to sign you up – faster than a human ever could.  
👉 Perfect (back then) for grabbing good shifts without constantly refreshing your inbox.

## ❌ Why is it archived?

Tesco has completely moved away from eShift to other systems worldwide.  
This repository remains online **only for historical and educational purposes**.

## ⚠️ Disclaimer

> **FOR EDUCATIONAL PURPOSES ONLY.**  
> No support. No docs. No guarantees.  
> If you know Python and enjoy reverse engineering, you might find it interesting.  
> Otherwise – it's just a piece of history now.

## 🧠 How it worked

1. Connected to your inbox via IMAP (e.g. Gmail)
2. When a new eShift email arrived, it extracted the shift booking links
3. Automatically opened those links using `app.py` to claim the shifts
4. Login credentials were stored in `appointments.db`

## 🔧 Requirements (historical)

- Python 3.x
- `.env` file with IMAP settings (email server, login, password)
- A filled-out `appointments.db` with your eShift login (see example)

## 📁 Files & Structure

- `appointments.db` – contained your eShift credentials (example included)
- `.env` – contained `IMAP_SERVER`, `EMAIL`, `EMAIL_PASSWORD`, etc.

## 🤷‍♂️ Documentation?

None was ever written – it was a quick hack that worked at the time.  
It’s now preserved here as-is, for nostalgia and study.

---

🧙‍♂️ Nerds only past this point. This code is a fossil from the Tesco eShift era.
