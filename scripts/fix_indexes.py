#!/usr/bin/env python3
"""
Fix all index definitions in models to remove the old postgresql_indexes syntax.
"""
import os
import re

def fix_table_args(content):
    """Remove __table_args__ with postgresql_indexes."""
    # Pattern to match __table_args__ with postgresql_indexes
    pattern = r'    # (?:Constraints|Indexes)\n    __table_args__ = \(\n        \{[\'"]postgresql_indexes[\'"]:[^}]+\}\n    \)'
    
    # Replace with empty string
    content = re.sub(pattern, '', content, flags=re.MULTILINE | re.DOTALL)
    
    return content

def main():
    models_dir = "src/infrastructure/database/models"
    
    for filename in os.listdir(models_dir):
        if filename.endswith('.py') and filename != '__init__.py':
            filepath = os.path.join(models_dir, filename)
            
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Fix the content
            new_content = fix_table_args(content)
            
            # Only write if changed
            if new_content != content:
                with open(filepath, 'w') as f:
                    f.write(new_content)
                print(f"✅ Fixed {filename}")
            else:
                print(f"ℹ️  No changes needed for {filename}")

if __name__ == "__main__":
    main()