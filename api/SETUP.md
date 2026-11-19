# Setup: listings admin (Vercel Blob, same as sellmybusinessohio.com)

No new paid service. Four steps, about 5 minutes.

1. **Upload files to GitHub.** Upload everything in this folder to the repo root, including `package.json` and the `api/` folder.
2. **Create a Blob store.** Vercel > your kyleatwood project > **Storage** > Create > **Blob**. Choose **Public**. Connect it to this project (all environments). Vercel adds `BLOB_READ_WRITE_TOKEN` automatically.
3. **Add two environment variables** (Settings > Environment Variables):
   - `ADMIN_PASSWORD` = the password you want to log in with
   - `SESSION_SECRET` = any long random string, 24+ characters
4. **Redeploy** (Deployments > latest > Redeploy). Then go to `/admin`, log in, and add a listing.

Notes
- Listings are one small file (`data/listings.json`) in your Blob store; photos go in `photos/`.
- Public pages may take up to about 1 minute to show a change. The admin always shows the latest.
- Wrong password 5 times = 15 minute lockout for that visitor.
- Vercel Hobby is for non-commercial use; a business site should be on Pro.
