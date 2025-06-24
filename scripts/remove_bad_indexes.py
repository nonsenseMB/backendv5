#!/usr/bin/env python3
"""
Remove all problematic __table_args__ with postgresql_indexes.
"""
import os
import re

def remove_table_args(content):
    """Remove problematic __table_args__ definitions."""
    # Pattern to match entire __table_args__ block with postgresql_indexes
    pattern = r'    # (?:Indexes|Constraints)\n    __table_args__ = \(\n(?:        .*\n)*?    \)\n'
    
    # Find all matches and only remove those with postgresql_indexes
    def replacer(match):
        if 'postgresql_indexes' in match.group(0):
            return ''
        return match.group(0)
    
    content = re.sub(pattern, replacer, content, flags=re.MULTILINE)
    
    return content

def main():
    models_dir = "src/infrastructure/database/models"
    
    for filename in os.listdir(models_dir):
        if filename.endswith('.py') and filename != '__init__.py':
            filepath = os.path.join(models_dir, filename)
            
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Count occurrences before
            before_count = content.count('postgresql_indexes')
            
            # Fix the content
            new_content = remove_table_args(content)
            
            # Count occurrences after
            after_count = new_content.count('postgresql_indexes')
            
            # Only write if changed
            if before_count != after_count:
                with open(filepath, 'w') as f:
                    f.write(new_content)
                print(f"✅ Fixed {filename} (removed {before_count - after_count} problematic index definitions)")
            else:
                print(f"ℹ️  No changes needed for {filename}")

if __name__ == "__main__":
    main()