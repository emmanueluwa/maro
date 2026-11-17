# Maro

An AI research companion for PhD students who struggle with the executive-function side of academic work: starting, structuring, sticking to a plan, and finding trustworthy sources fast.

Maro is designed around how the work actually breaks down, not around generic productivity advice. It helps with:

- **Dictate:** speak your ideas, and Maro groups them into sections. Use your own categories, or let Maro group by its knowledge of the field. Every grouping shows its reasoning and can be undone. Your words are never rewritten.
- **Redact and Find:** remove identifying details from a scenario, then find reputable papers on solutions, with the exact passage and page number for every quote.
- **Plan and Today:** a pinned plan, one current task at a time, a timer, and one-tap re-planning when you overrun. Maro learns how long your tasks really take.

## Principles

- Maro organizes and retrieves. It never writes the report.
- Citations come from real scholarly databases, and every quote is verified word for word against the paper before it is shown.
- Identifying details are removed before any text is analysed, and audio is deleted right after transcription.

## Tech stack

| Layer                     | Choice                                  |
| ------------------------- | --------------------------------------- |
| Backend                   | Python, FastAPI                         |
| Frontend (planned)        | Next.js, React, TypeScript              |
| Database (planned)        | PostgreSQL                              |
| Background work (planned) | Redis-backed workers                    |
| AI (planned)              | Claude, behind a provider-neutral layer |
| Package management        | [uv](https://docs.astral.sh/uv/)        |
| Hosting                   | AWS                                     |

## Getting started

### Prerequisites

- [uv](https://docs.astral.sh/uv/getting-started/installation/). It installs the correct Python version and creates the virtual environment for you.

### Set up

```bash
git clone <repository-url> maro
cd maro/backend
uv sync
```

`uv sync` creates `backend/.venv` and installs the exact versions recorded in `uv.lock`. You never need to activate the environment by hand, because `uv run` always uses it.

### Run the API

From the `backend` folder:

```bash
uv run uvicorn app.main:app --reload
```

Then open http://localhost:8000/health. You should see:

```json
{ "status": "ok", "environment": "development" }
```

Interactive API documentation is at http://localhost:8000/docs in development. It is disabled in production.

### Run the tests

```bash
uv run pytest
```

```
APP_ENVIRONMENT=development
APP_LOG_LEVEL=DEBUG
APP_ALLOWED_ORIGINS=["http://localhost:3000"]
APP_DATABASE_URL=postgresql+asyncpg://maro:maro@localhost:5432/maro
```

Invalid values stop the app at startup. In production, the app also refuses to start with the development database URL.
