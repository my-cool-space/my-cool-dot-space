#!/usr/bin/env node

require('dotenv').config();
const { Client, Databases } = require('node-appwrite');

async function recreateAdminSettings() {
    console.log('🔧 Recreating Admin Settings Collection...');
    
    const client = new Client();
    client
        .setEndpoint(process.env.APPWRITE_ENDPOINT)
        .setProject(process.env.APPWRITE_PROJECT_ID)
        .setKey(process.env.APPWRITE_API_KEY);
    
    const databases = new Databases(client);
    
    try {
        // Delete existing collection
        console.log('🗑️ Deleting existing admin_settings collection...');
        try {
            await databases.deleteCollection(
                process.env.APPWRITE_DATABASE_ID,
                'admin_settings'
            );
            console.log('✅ Existing collection deleted');
        } catch (error) {
            console.log('Collection may not exist:', error.message);
        }
        
        // Wait a moment for deletion to complete
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        console.log('📝 Creating new admin_settings collection...');
        
        // Create the collection
        const collection = await databases.createCollection(
            process.env.APPWRITE_DATABASE_ID,
            'admin_settings',
            'Admin Settings'
        );
        
        console.log('✅ Collection created:', collection.name);
        
        // Wait a moment for collection to be ready
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // Create attributes one by one with delays
        console.log('📝 Creating attributes...');
        
        await databases.createIntegerAttribute(
            process.env.APPWRITE_DATABASE_ID,
            'admin_settings',
            'max_subdomains',
            true, // required
            1, // min
            100 // max
        );
        console.log('✅ Created max_subdomains attribute');
        
        // Wait between attribute creations
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        await databases.createStringAttribute(
            process.env.APPWRITE_DATABASE_ID,
            'admin_settings',
            'domain_name',
            255, // size
            true // required
        );
        console.log('✅ Created domain_name attribute');
        
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        await databases.createBooleanAttribute(
            process.env.APPWRITE_DATABASE_ID,
            'admin_settings',
            'auto_approve',
            true // required
        );
        console.log('✅ Created auto_approve attribute');
        
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        await databases.createBooleanAttribute(
            process.env.APPWRITE_DATABASE_ID,
            'admin_settings',
            'maintenance_mode',
            true // required
        );
        console.log('✅ Created maintenance_mode attribute');
        
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        await databases.createDatetimeAttribute(
            process.env.APPWRITE_DATABASE_ID,
            'admin_settings',
            'created_at',
            true // required
        );
        console.log('✅ Created created_at attribute');
        
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        await databases.createDatetimeAttribute(
            process.env.APPWRITE_DATABASE_ID,
            'admin_settings',
            'updated_at',
            false // not required
        );
        console.log('✅ Created updated_at attribute');
        
        console.log('🎉 Admin settings collection recreated successfully!');
        
    } catch (error) {
        console.error('❌ Error recreating admin settings collection:', error.message);
        console.error('Full error:', error);
        process.exit(1);
    }
}

// Run the recreation
recreateAdminSettings();
