const functions = require("firebase-functions");
const admin = require("firebase-admin");
admin.initializeApp();

// Public function: Accessible without authentication
exports.publicFunction = functions.https.onRequest((request, response) => {
  response.send("Hello from public function!");
});

// Private function: Requires authentication (simulated check)
exports.privateFunction = functions.https.onCall((data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError(
      "unauthenticated",
      "The function must be called while authenticated."
    );
  }
  return { message: "Hello from private function!" };
});

// Seeding function: Populates data for extraction testing
exports.seedData = functions.https.onRequest(async (req, res) => {
  try {
    // Seed Firestore
    await admin.firestore().collection('insecure_collection').doc('secret_doc').set({
      secret: "flag{firestore_extracted}",
      description: "This data should be visible to FireScan"
    });

    // Seed RTDB
    await admin.database().ref('insecure_node').set({
      secret: "flag{rtdb_extracted}",
      config: {
        debug: true,
        key: "12345"
      }
    });

    // Seed Storage
    // Note: This requires the App Engine default service account to have storage permissions
    try {
        const bucket = admin.storage().bucket();
        const file = bucket.file('insecure/secret.txt');
        await file.save("flag{storage_extracted}");
    } catch (e) {
        console.warn("Storage seeding failed (might need permissions):", e);
    }

    res.send("Data seeded successfully! (Storage might fail if default bucket not configured)");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error seeding data: " + error.message);
  }
});
