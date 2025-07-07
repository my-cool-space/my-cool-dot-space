const sdk = require('node-appwrite');

// This is your Appwrite function
// To execute this function, uncomment the code below and deploy the function.

module.exports = async function (req, res) {
    const client = new sdk.Client();
    
    // You can remove services you don't use
    const account = new sdk.Account(client);
    const avatars = new sdk.Avatars(client);
    const databases = new sdk.Databases(client);
    const functions = new sdk.Functions(client);
    const health = new sdk.Health(client);
    const locale = new sdk.Locale(client);
    const storage = new sdk.Storage(client);
    const teams = new sdk.Teams(client);
    const users = new sdk.Users(client);

    if (
        !req.variables['APPWRITE_FUNCTION_ENDPOINT'] ||
        !req.variables['APPWRITE_FUNCTION_API_KEY']
    ) {
        console.warn("Environment variables are not set. Function cannot use Appwrite SDK.");
    } else {
        client
            .setEndpoint(req.variables['APPWRITE_FUNCTION_ENDPOINT'])
            .setProject(req.variables['APPWRITE_FUNCTION_PROJECT_ID'])
            .setKey(req.variables['APPWRITE_FUNCTION_API_KEY'])
            .setSelfSigned(true);
    }

    try {
        const payload = JSON.parse(req.variables['APPWRITE_FUNCTION_DATA'] || '{}');
        const { subdomain, target_url, record_type } = payload;

        if (!subdomain || !target_url) {
            return res.json({
                error: 'Missing required parameters: subdomain and target_url'
            }, 400);
        }

        // Porkbun API credentials from environment
        const API_KEY = req.variables['PORKBUN_API_KEY'];
        const SECRET_KEY = req.variables['PORKBUN_SECRET_KEY'];
        const BASE_DOMAIN = req.variables['BASE_DOMAIN'] || 'my-cool.space';

        if (!API_KEY || !SECRET_KEY) {
            return res.json({
                error: 'Porkbun API credentials not configured'
            }, 500);
        }

        // Determine record type and content based on the record_type parameter
        let recordType, recordContent;
        
        switch (record_type) {
            case 'redirect':
                // For redirects, we'll use URL forwarding or create a CNAME to a redirect service
                // For now, let's extract the domain from the URL and create a CNAME
                try {
                    const url = new URL(target_url);
                    recordType = 'CNAME';
                    recordContent = url.hostname;
                } catch (e) {
                    return res.json({
                        error: 'Invalid target URL format for redirect'
                    }, 400);
                }
                break;
                
            case 'cname':
                recordType = 'CNAME';
                recordContent = target_url.replace(/^https?:\/\//, '').replace(/\/$/, ''); // Remove protocol and trailing slash
                break;
                
            case 'a':
                recordType = 'A';
                // Validate IP address format
                const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
                if (!ipRegex.test(target_url)) {
                    return res.json({
                        error: 'Invalid IP address format for A record'
                    }, 400);
                }
                recordContent = target_url;
                break;
                
            default:
                return res.json({
                    error: 'Invalid record type. Must be: redirect, cname, or a'
                }, 400);
        }

        // Porkbun API request
        const porkbunResponse = await fetch(`https://porkbun.com/api/json/v3/dns/create/${BASE_DOMAIN}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                secretapikey: SECRET_KEY,
                apikey: API_KEY,
                name: subdomain,
                type: recordType,
                content: recordContent,
                ttl: 300 // 5 minutes TTL for faster propagation
            })
        });

        const porkbunResult = await porkbunResponse.json();

        if (porkbunResult.status === 'SUCCESS') {
            console.log(`DNS record created successfully for ${subdomain}.${BASE_DOMAIN}`);
            return res.json({
                success: true,
                message: `DNS record created for ${subdomain}.${BASE_DOMAIN}`,
                recordId: porkbunResult.id,
                recordType: recordType,
                recordContent: recordContent
            });
        } else {
            console.error('Porkbun API error:', porkbunResult);
            return res.json({
                error: 'Failed to create DNS record: ' + (porkbunResult.message || 'Unknown error')
            }, 500);
        }

    } catch (error) {
        console.error('Function execution error:', error);
        return res.json({
            error: 'Internal server error: ' + error.message
        }, 500);
    }
};
