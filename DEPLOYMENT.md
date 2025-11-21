# Deployment Guide - Render

## Prerequisites
1. GitHub account with your code repository
2. Render account (free tier available)

## Step-by-Step Deployment

### 1. Prepare Your Repository
```bash
git add .
git commit -m "Prepare for Render deployment"
git push origin main
```

### 2. Create Render Web Service
1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click "New" → "Web Service"
3. Connect your GitHub repository
4. Configure the service:
   - **Name**: `cyberguard-ai`
   - **Environment**: `Python 3`
   - **Build Command**: `./build.sh`
   - **Start Command**: `gunicorn cybersecurity.wsgi:application --bind 0.0.0.0:$PORT`

### 3. Environment Variables
Add these environment variables in Render:

**Required:**
- `DJANGO_SETTINGS_MODULE` = `cybersecurity.settings_production`
- `SECRET_KEY` = `your-secret-key-here`
- `EMAIL_HOST_PASSWORD` = `your-gmail-app-password`

**Optional:**
- `EMAIL_HOST_USER` = `obernard377@gmail.com`
- `DATABASE_URL` = (Render will provide this if using PostgreSQL)

### 4. Database Setup (Optional)
For persistent data, add a PostgreSQL database:
1. In Render Dashboard, click "New" → "PostgreSQL"
2. Name it `cyberguard-db`
3. Copy the connection details to your web service environment variables

### 5. Deploy
1. Click "Create Web Service"
2. Render will automatically build and deploy your app
3. Your app will be available at: `https://your-app-name.onrender.com`

## Post-Deployment

### Create Admin User
```bash
# In Render shell (or locally with production DB)
python manage.py createsuperuser
```

### Test the System
1. Visit your deployed URL
2. Test attack detection: `https://your-app.onrender.com/test-attack/`
3. Access admin: `https://your-app.onrender.com/admin/`
4. Check dashboards: `https://your-app.onrender.com/dashboard/`

## Important Notes

### Security
- The app uses HTTPS in production
- Email alerts will work with your Gmail App Password
- Firewall system will protect against real attacks

### Limitations on Free Tier
- App may sleep after 15 minutes of inactivity
- 512MB RAM limit
- 750 hours/month limit

### Monitoring
- Check Render logs for any issues
- Email alerts will continue to work
- Database persists between deployments

## Troubleshooting

### Common Issues
1. **Build fails**: Check Python version in `runtime.txt`
2. **Static files not loading**: Ensure WhiteNoise is configured
3. **Database errors**: Verify PostgreSQL connection
4. **Email not working**: Check Gmail App Password

### Support
- Render Documentation: https://render.com/docs
- Django Deployment Guide: https://docs.djangoproject.com/en/4.2/howto/deployment/