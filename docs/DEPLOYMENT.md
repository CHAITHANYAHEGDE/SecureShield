# Deployment Guide

SecureShield is architected for local demonstration and conference presentations. 

## Vercel + Render Deployment Consideration

The application can theoretically be deployed to cloud services such as Vercel (Frontend) and Render (Backend). Configuration files (`vercel.json` and `render.yaml`) are provided to facilitate this.

### Render Configuration (Backend)
Render will host the FastAPI service.
- **Environment Variables**: You must define `SECURESHIELD_FRONTEND_URL` on Render to map to your Vercel URL to enable strict CORS.
- **Root Path**: Ensure the Start Command uses the `backend/` directory or appropriately sets the `PYTHONPATH`.

### Vercel Configuration (Frontend)
Vercel hosts the React Single Page Application.
- **Environment Variables**: Define `VITE_API_BASE_URL` in the Vercel dashboard to point to your Render backend instance (e.g., `https://your-backend.onrender.com/api`).

### Security Limitation (Not Fully Production Ready)
**WARNING**: This application is **NOT READY** for a completely public, open-internet production deployment without further security engineering.
While the backend has been hardened against path traversals, XSS, and verbose error leakage, it currently lacks:
1. **Authentication**: There is no JWT, OAuth, or session management. Anyone with the URL can access the API.
2. **Rate Limiting**: It lacks Redis-backed request throttling to prevent DoS.

Deploy to the public internet at your own discretion, and exclusively for controlled demonstration purposes.
