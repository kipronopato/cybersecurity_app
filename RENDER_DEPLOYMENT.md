# Render Deployment Guide for CyberGuard AI

## Quick Deployment Steps

### 1. Prepare Your Repository
Ensure all files are committed to your Git repository:
```bash
git add .
git commit -m "Prepare for Render deployment"
git push origin main
```

### 2. Create Render Account
- Go to [render.com](https://render.com)
- Sign up with your GitHub account

### 3. Deploy Using render.yaml (Recommended)
1. In Render dashboard, click "New" → "Blueprint"
2. Connect your GitHub repository
3. Render will automatically detect `render.yaml` and create:
   - Web service for the Django app
   - PostgreSQL database

### 4. Manual Deployment (Alternative)
If not using render.yaml:

#### Create PostgreSQL Database
1. Click "New" → "PostgreSQL"
2. Name: `cyberguard-db`
3. Database Name: `cybersecurity_db`
4. User: `postgres`
5. Note the connection details

#### Create Web Service
1. Click "New" → "Web Service"
2. Connect your repository
3. Configure:
   - **Name**: `cyberguard-ai`
   - **Environment**: `Python 3`
   - **Build Command**: `./build.sh`
   - **Start Command**: `gunicorn cybersecurity.wsgi:application --bind 0.0.0.0:$PORT --env DJANGO_SETTINGS_MODULE=cybersecurity.settings_production`

### 5. Set Environment Variables
In your web service settings, add:

**Required Variables:**
- `DJANGO_SETTINGS_MODULE` = `cybersecurity.settings_production`
- `SECRET_KEY` = (generate a new secret key)
- `EMAIL_HOST_USER` = `obernard377@gmail.com`
- `EMAIL_HOST_PASSWORD` = (your Gmail app password)

**Database Variables (if not using DATABASE_URL):**
- `DATABASE_NAME` = `cybersecurity_db`
- `DATABASE_USER` = `postgres`
- `DATABASE_PASSWORD` = (from your database settings)
- `DATABASE_HOST` = (from your database settings)
- `DATABASE_PORT` = `5432`

### 6. Deploy
1. Click "Deploy Latest Commit"
2. Monitor the build logs
3. Once deployed, your app will be available at `https://your-app-name.onrender.com`

## Important Notes

### Security
- Never commit sensitive data like passwords or secret keys
- Use environment variables for all sensitive configuration
- The app uses HTTPS by default on Render

### Database
- Render provides a `DATABASE_URL` environment variable automatically
- The app will use this if available, otherwise falls back to individual variables

### Static Files
- Static files are handled by WhiteNoise
- No additional configuration needed

### Email Configuration
- You need a Gmail App Password (not your regular password)
- Go to Google Account Settings → Security → 2-Step Verification → App Passwords

### Monitoring
- Check Render logs for any deployment issues
- The app includes comprehensive logging for security events

## Troubleshooting

### Build Fails
- Check that all dependencies are in `requirements-minimal.txt`
- Ensure `build.sh` has execute permissions

### Database Connection Issues
- Verify DATABASE_URL is set correctly
- Check PostgreSQL database is running

### Static Files Not Loading
- Ensure `collectstatic` runs in build script
- Check STATIC_ROOT and STATICFILES_STORAGE settings

### Email Not Working
- Verify Gmail App Password is correct
- Check EMAIL_HOST_USER and EMAIL_HOST_PASSWORD variables

## Post-Deployment

### Create Admin User
Use Render's shell feature:
```bash
python manage.py createsuperuser
```

### Test the System
1. Visit your app URL
2. Go to `/admin/` to access admin panel
3. Test attack detection at `/test-attack/`
4. Check firewall functionality

### Monitor Security
- Check `/security/alerts/` for security events
- Monitor Render logs for system health
- Set up email notifications for critical alerts

## Scaling
- Render automatically handles scaling
- Consider upgrading to paid plans for production use
- Monitor resource usage in Render dashboard