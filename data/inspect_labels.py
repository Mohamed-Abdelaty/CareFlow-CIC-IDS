import os
import pandas as pd
import glob

raw_dir = "/data/raw"
csv_files = sorted(glob.glob(os.path.join(raw_dir, "*.csv")))

print(f"Found {len(csv_files)} CSV files in {raw_dir}:")
for f in csv_files:
    fname = os.path.basename(f)
    print(f"\nAnalyzing {fname}...")
    try:
        # read just the Label column to see distribution
        # some files might have different case or spaces in column headers, so let's inspect columns first
        df_cols = pd.read_csv(f, nrows=2)
        # find column that matches 'label' (case insensitive)
        label_col = [c for c in df_cols.columns if 'label' in c.lower()]
        if not label_col:
            print(f"  Warning: No label column found! Columns: {list(df_cols.columns)}")
            continue
        col_name = label_col[0]
        
        # read the Label column in chunks to find distribution
        counts = {}
        for chunk in pd.read_csv(f, usecols=[col_name], chunksize=100000, low_memory=False):
            # clean label strings
            chunk[col_name] = chunk[col_name].astype(str).str.strip()
            # drop header rows that might be duplicated in CSV
            chunk = chunk[chunk[col_name].str.lower() != 'label']
            for val, cnt in chunk[col_name].value_counts().items():
                counts[val] = counts.get(val, 0) + cnt
        
        print(f"  Column: '{col_name}'")
        for val, cnt in counts.items():
            print(f"    - {val}: {cnt:,}")
    except Exception as e:
        print(f"  Error reading {fname}: {e}")
