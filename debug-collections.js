#!/usr/bin/env node

require('dotenv').config();
const { Client, Databases } = require('node-appwrite');

async function debugCollections() {
    const client = new Client();
    client
        .setEndpoint(process.env.APPWRITE_ENDPOINT)
        .setProject(process.env.APPWRITE_PROJECT_ID)
        .setKey(process.env.APPWRITE_API_KEY);
    
    const databases = new Databases(client);
    
    try {
        console.log('📋 Listing all collections...');
        const collections = await databases.listCollections(process.env.APPWRITE_DATABASE_ID);
        
        console.log(`Found ${collections.total} collections:`);
        collections.collections.forEach(collection => {
            console.log(`- ${collection.$id}: ${collection.name}`);
        });
        
        console.log('\n🔍 Checking admin_settings collection specifically...');
        try {
            const adminSettings = await databases.getCollection(
                process.env.APPWRITE_DATABASE_ID,
                'admin_settings'
            );
            console.log('✅ admin_settings collection found:', adminSettings.name);
            console.log('📋 Attributes:');
            adminSettings.attributes.forEach(attr => {
                console.log(`  - ${attr.key}: ${attr.type} (required: ${attr.required})`);
            });
        } catch (error) {
            console.log('❌ admin_settings collection not found:', error.message);
        }
        
    } catch (error) {
        console.error('❌ Error:', error.message);
    }
}

debugCollections();
