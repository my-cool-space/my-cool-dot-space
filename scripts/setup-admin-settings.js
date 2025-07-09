#!/usr/bin/env node

/**
 * Setup Admin Settings Collection
 * 
 * This script creates the admin_settings collection in Appwrite with the proper attributes.
 * Run this once to set up the persistent admin settings storage.
 */

require('dotenv').config();
const { Client, Databases, ID } = require('node-appwrite');

async function setupAdminSettings() {
    console.log('🔧 Setting up Admin Settings Collection...');
    
    // Initialize Appwrite client
    const client = new Client();
    client
        .setEndpoint(process.env.APPWRITE_ENDPOINT)
        .setProject(process.env.APPWRITE_PROJECT_ID)
        .setKey(process.env.APPWRITE_API_KEY);
    
    const databases = new Databases(client);
    
    try {
        // Check if collection already exists
        const collectionId = process.env.APPWRITE_SETTINGS_COLLECTION_ID || 'admin_settings';
        
        try {
            const existingCollection = await databases.getCollection(
                process.env.APPWRITE_DATABASE_ID,
                collectionId
            );
            console.log('✅ Admin settings collection already exists:', existingCollection.name);
            return;
        } catch (error) {
            if (error.code !== 404) {
                throw error;
            }
            // Collection doesn't exist, create it
        }
        
        console.log('📝 Creating admin_settings collection...');
        
        // Create the collection
        const collection = await databases.createCollection(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'Admin Settings'
        );
        
        console.log('✅ Collection created:', collection.name);
        
        // Create attributes
        console.log('📝 Creating attributes...');
        
        await databases.createIntegerAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'max_subdomains',
            true, // required
            1, // min
            100 // max
        );
        console.log('✅ Created max_subdomains attribute');
        
        await databases.createStringAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'domain_name',
            255, // size
            true // required
        );
        console.log('✅ Created domain_name attribute');
        
        await databases.createBooleanAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'auto_approve',
            true // required
        );
        console.log('✅ Created auto_approve attribute');
        
        await databases.createBooleanAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'maintenance_mode',
            true // required
        );
        console.log('✅ Created maintenance_mode attribute');
        
        await databases.createDatetimeAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'created_at',
            true // required
        );
        console.log('✅ Created created_at attribute');
        
        await databases.createDatetimeAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'updated_at',
            false // not required
        );
        console.log('✅ Created updated_at attribute');
        
        console.log('🎉 Admin settings collection setup complete!');
        console.log(`📋 Collection ID: ${collectionId}`);
        console.log('💡 Make sure to set APPWRITE_SETTINGS_COLLECTION_ID in your .env file if different from "admin_settings"');
        
    } catch (error) {
        console.error('❌ Error setting up admin settings collection:', error.message);
        process.exit(1);
    }
}

async function setupAlertsCollection() {
    console.log('🔧 Setting up Alerts Collection...');
    
    // Initialize Appwrite client
    const client = new Client();
    client
        .setEndpoint(process.env.APPWRITE_ENDPOINT)
        .setProject(process.env.APPWRITE_PROJECT_ID)
        .setKey(process.env.APPWRITE_API_KEY);
    
    const databases = new Databases(client);
    
    try {
        const collectionId = process.env.APPWRITE_ALERTS_COLLECTION_ID || 'alerts';
        
        try {
            const existingCollection = await databases.getCollection(
                process.env.APPWRITE_DATABASE_ID,
                collectionId
            );
            console.log('✅ Alerts collection already exists:', existingCollection.name);
            return;
        } catch (error) {
            if (error.code !== 404) {
                throw error;
            }
        }
        
        console.log('📝 Creating alerts collection...');
        
        const collection = await databases.createCollection(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'Alerts'
        );
        
        console.log('✅ Collection created:', collection.name);
        
        console.log('📝 Creating attributes for alerts...');
        
        await databases.createStringAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'title',
            255,
            true
        );
        console.log('✅ Created title attribute');
        
        await databases.createStringAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'message',
            1000,
            true
        );
        console.log('✅ Created message attribute');
        
        await databases.createStringAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'url',
            2048,
            false
        );
        console.log('✅ Created url attribute');
        
        await databases.createStringAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'subdomain',
            255,
            false
        );
        console.log('✅ Created subdomain attribute');
        
        await databases.createStringAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'status',
            50,
            true, // required
            false, // isArray
            'pending', // defaultValue
            false, // isEncrypted
            ['approved', 'pending', 'rejected'] // elements (enum)
        );
        console.log('✅ Created status attribute');
        
        await databases.createDatetimeAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'created_at',
            true
        );
        console.log('✅ Created created_at attribute');
        
        await databases.createStringAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'created_by',
            255,
            true
        );
        console.log('✅ Created created_by attribute');

        await databases.createDatetimeAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'reviewed_at',
            false
        );
        console.log('✅ Created reviewed_at attribute');

        await databases.createStringAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'reviewed_by',
            255,
            false
        );
        console.log('✅ Created reviewed_by attribute');

        await databases.createStringAttribute(
            process.env.APPWRITE_DATABASE_ID,
            collectionId,
            'rejection_reason',
            1000,
            false
        );
        console.log('✅ Created rejection_reason attribute');
        
        console.log('🎉 Alerts collection setup complete!');
        console.log(`📋 Collection ID: ${collectionId}`);
        console.log('💡 Make sure to set APPWRITE_ALERTS_COLLECTION_ID in your .env file if different from "alerts"');
        
    } catch (error) {
        console.error('❌ Error setting up alerts collection:', error.message);
        process.exit(1);
    }
}

// Run the setup
(async () => {
    await setupAdminSettings();
    await setupAlertsCollection();
})();
