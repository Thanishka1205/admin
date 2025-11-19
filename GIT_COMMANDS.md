# Git Commands for This Project

## Initial Setup (First Time)

```bash
# Navigate to project directory
cd Interview_questions_approach_1

# Initialize git repository
git init

# Configure git (if not done globally)
git config user.name "Your Name"
git config user.email "your.email@example.com"

# Add all files (respects .gitignore)
git add .

# Check what will be committed
git status

# Create initial commit
git commit -m "Initial commit: Interview assessment system"

# Add remote repository (replace with your repo URL)
git remote add origin https://github.com/yourusername/your-repo-name.git

# Push to remote
git branch -M main
git push -u origin main
```

## Regular Workflow (After Initial Setup)

```bash
# Check status
git status

# Add specific files
git add filename.py
# Or add all changes
git add .

# Commit changes
git commit -m "Description of changes"

# Push to remote
git push
```

## Important Notes

- **Never commit `.env` file** - It's in `.gitignore` for security
- **Always check `git status`** before committing to see what will be added
- **Use descriptive commit messages** to track changes

## If You Need to Update Remote URL

```bash
# Remove existing remote
git remote remove origin

# Add new remote
git remote add origin https://github.com/yourusername/new-repo-name.git

# Push to new remote
git push -u origin main
```

