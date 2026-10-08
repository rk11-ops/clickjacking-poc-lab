# Publish on GitHub Pages

1. Create a new GitHub repository, for example `clickjacking-poc-lab`.
2. Upload the contents of this folder to the repository root. Do not upload the parent folder as one nested directory.
3. Keep the branch name `main`.
4. Open **Settings → Pages** in the repository.
5. Under **Build and deployment**, select **GitHub Actions**.
6. Push/commit the files. The included workflow will deploy the site.
7. After the workflow finishes, GitHub will show the Pages URL under Settings → Pages.

For a custom domain, configure the domain under Settings → Pages and create the DNS records GitHub shows you.

### Browser-only quick publish

A simpler alternative is Settings → Pages → Deploy from a branch → `main` → `/ (root)`.

Use only against targets you own or are explicitly authorized to assess.
