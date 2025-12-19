# 🔐 Salesforce Connected App Setup Guide

Complete guide to set up OAuth 2.0 authentication for SSO-enabled Salesforce orgs.

## 🎯 Why OAuth Instead of Security Token?

### Security Token Issues with SSO:
- ❌ **Disabled in SSO orgs** (SAML, Azure AD, Okta, Google)
- ❌ Users don't have Salesforce passwords
- ❌ Insecure for enterprise applications
- ❌ Cannot be revoked individually
- ❌ No audit trail

### OAuth 2.0 Benefits:
- ✅ **Works with SSO** (SAML, Azure AD, Okta, Google)
- ✅ No password storage required
- ✅ Tokens can be revoked anytime
- ✅ Full audit trail
- ✅ MFA compliant
- ✅ Scoped permissions
- ✅ Enterprise-ready

---

## 📋 Step-by-Step Connected App Setup

### Step 1: Create Connected App in Salesforce

1. **Login to Salesforce**
   - Go to your Salesforce org
   - Use your SSO login (Azure AD/Okta/Google/SAML)

2. **Navigate to Setup**
   - Click the gear icon ⚙️ (top right)
   - Select **Setup**

3. **Go to App Manager**
   - In Quick Find box, search: **App Manager**
   - Click **App Manager** under Apps

4. **Create New Connected App**
   - Click **New Connected App** button
   - Fill in the form:

#### Basic Information:
```
Connected App Name: Salesforce Security Analyzer
API Name: Salesforce_Security_Analyzer (auto-generated)
Contact Email: your-email@company.com
```

#### API (Enable OAuth Settings):
- ✅ Check **Enable OAuth Settings**

**Callback URL** (Important!):
```
https://login.salesforce.com/services/oauth2/callback
http://localhost:7860/oauth/callback
```
(Add both - first for production, second for local testing)

**Selected OAuth Scopes** - Add these:
- `Full access (full)` - For comprehensive org analysis
- `Perform requests at any time (refresh_token, offline_access)` - For token refresh
- `Access and manage your data (api)` - For SOQL queries

#### Advanced Settings:
- ✅ Check **Enable Client Credentials Flow** (for server-to-server)
- ✅ Check **Require Secret for Web Server Flow** (security)
- ❌ UNCHECK **Require Secret for Refresh Token Flow** (flexibility)

5. **Save the Connected App**
   - Click **Save**
   - Click **Continue** on the warning popup

6. **Wait 2-10 Minutes**
   - Salesforce needs time to propagate the app
   - ⏰ **Important**: Don't proceed until 10 minutes have passed

---

### Step 2: Get OAuth Credentials

1. **Return to App Manager**
   - Setup → App Manager
   - Find your "Salesforce Security Analyzer" app

2. **Click the dropdown** (▼) next to the app
   - Select **View**

3. **Copy These Values** (You'll need them):

**Consumer Key (Client ID)**:
```
Example: 3MVG9_XwsqeYoue1Vy7Z8kQp_h4zR5kH...
```
⚠️ This is PUBLIC - safe to share

**Consumer Secret (Client Secret)**:
- Click **Click to reveal**
```
Example: 8234567890123456789
```
⚠️ Keep this SECRET - treat like a password

**Save these securely!** You'll enter them in the Hugging Face app.

---

### Step 3: Configure API Access (Optional but Recommended)

1. **Create Permission Set** (if needed)
   - Setup → Permission Sets
   - Click **New**
   - Label: `Security Analyzer API Access`
   - Click **Save**

2. **Add System Permissions**:
   - Click **System Permissions**
   - Click **Edit**
   - Enable:
     - ✅ **API Enabled**
     - ✅ **View Setup and Configuration**
     - ✅ **View All Data** (read-only analysis)
   - Click **Save**

3. **Assign to Users**:
   - On Permission Set page → **Manage Assignments**
   - Click **Add Assignments**
   - Select users who will use the analyzer
   - Click **Assign**

---

### Step 4: Configure IP Relaxation (Production Only)

For production deployments on Hugging Face:

1. **Edit Connected App**
   - App Manager → Find your app → **Edit**

2. **IP Relaxation**
   - Under OAuth Policies
   - IP Relaxation: Select **Relax IP restrictions**
   - This allows access from Hugging Face servers

3. **Save**

---

## 🔒 Security Best Practices

### 1. **Use Separate Connected Apps for Each Environment**

```
Development:   Security_Analyzer_Dev
Staging:       Security_Analyzer_Stage  
Production:    Security_Analyzer_Prod
```

### 2. **Limit OAuth Scopes**

Only grant necessary permissions:
- ❌ Don't use `full` scope in production
- ✅ Use specific scopes: `api`, `refresh_token`

### 3. **Enable Session Security**

Setup → Session Settings:
- ✅ Enable **clickjack protection**
- ✅ Enable **HTTPS required**
- ✅ Set **timeout value** appropriately

### 4. **Regular Audits**

Monitor usage:
- Setup → Login History
- Setup → API Usage
- Check for suspicious activity

### 5. **Revoke Tokens When Needed**

To revoke access:
- Setup → App Manager
- Your app → **Manage** → **Revoke** (for specific users)

---

## 🧪 Test Your Connected App

### Using cURL:

```bash
# Test OAuth token request
curl https://login.salesforce.com/services/oauth2/token \
  -X POST \
  -d "grant_type=password" \
  -d "client_id=YOUR_CONSUMER_KEY" \
  -d "client_secret=YOUR_CONSUMER_SECRET" \
  -d "username=YOUR_SSO_EMAIL" \
  -d "password=YOUR_SSO_PASSWORD"
```

**Expected Response:**
```json
{
  "access_token": "00D...xyz",
  "instance_url": "https://yourinstance.salesforce.com",
  "id": "https://login.salesforce.com/id/00D.../005...",
  "token_type": "Bearer",
  "issued_at": "1234567890",
  "signature": "abc..."
}
```

---

## 🐛 Troubleshooting

### Error: "invalid_client_id"
**Solution**: Wait 10 minutes after creating Connected App

### Error: "invalid_grant"
**Solution**: 
- Verify username/password correct
- Check if user has API access
- Ensure user is assigned to Connected App (if restricted)

### Error: "user hasn't approved this consumer"
**Solution**:
- Admin must pre-approve the app, OR
- User must manually authorize on first use

### Error: "IP restricted"
**Solution**:
- Add Hugging Face IPs to Network Access (Setup → Network Access)
- Or enable IP Relaxation in Connected App

---

## 📝 Checklist

Before using the analyzer:

- [ ] Connected App created and saved
- [ ] Waited 10 minutes for propagation
- [ ] Copied Consumer Key (Client ID)
- [ ] Copied Consumer Secret (Client Secret)  
- [ ] Created Permission Set (if needed)
- [ ] Assigned users to Permission Set
- [ ] Tested OAuth flow with cURL
- [ ] Ready to enter credentials in Hugging Face app

---

## 🔄 OAuth Flow in the Application

```
User enters:
  - Client ID (Consumer Key)
  - Client Secret (Consumer Secret)
  - Username (SSO email)
  - Password (SSO password)
    ↓
App requests token from Salesforce
    ↓
Salesforce validates and returns access_token
    ↓
App uses access_token for all API calls
    ↓
Token expires after 2 hours (automatic refresh)
```

---

## 📚 Additional Resources

- [Salesforce Connected Apps Documentation](https://help.salesforce.com/s/articleView?id=sf.connected_app_overview.htm)
- [OAuth 2.0 Reference](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_flows.htm)
- [Security Best Practices](https://developer.salesforce.com/docs/atlas.en-us.securityImplGuide.meta/securityImplGuide/)

---

**You're now ready to use OAuth authentication!** 🎉