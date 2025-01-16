# Import the required modules
import os
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading

# Define the FileComparator class
class FileComparator:
    def __init__(self, source_dir, destination_dir, status_callback=None):
        # Convert backslashes to forward slashes
        self.source_dir = os.path.normpath(source_dir).replace('\\', '/')
        self.destination_dir = os.path.normpath(destination_dir).replace('\\', '/')
        self.failed_operations = []  # Track failed operations
        self.file_database = {}  # Store file information
        self.update_status = status_callback or (lambda x: None)
        try:
            os.makedirs(self.destination_dir, exist_ok=True)
        except PermissionError:
            raise PermissionError(f"No permission to create destination directory: {self.destination_dir}")
    
    def scan_directory(self):
        """Recursively scan directory and build file database"""
        total_files = sum([len(files) for _, _, files in os.walk(self.source_dir)])
        processed_files = 0
        
        for root, _, files in os.walk(self.source_dir):
            for filename in files:
                try:
                    # Normalize all paths to use forward slashes
                    filepath = os.path.normpath(os.path.join(root, filename)).replace('\\', '/')
                    relpath = os.path.normpath(os.path.relpath(filepath, self.source_dir)).replace('\\', '/')
                    
                    if not os.path.exists(filepath):
                        self.update_status(f"Warning: File not found: {filepath}")
                        continue
                        
                    self.file_database[relpath] = {
                        'base_name': os.path.splitext(filename)[0],
                        'full_path': filepath,
                        'size': os.path.getsize(filepath)
                    }
                    processed_files += 1
                    
                    # Update progress (0-50% for scanning)
                    progress = (processed_files / total_files) * 50
                    self.update_progress(progress)
                    
                except (PermissionError, OSError) as e:
                    self.failed_operations.append((filename, str(e)))
        
        return total_files
    
    def get_file_pairs(self):
        """Find similar files from the database"""
        pairs = []
        files = list(self.file_database.keys())
        
        for i, file1 in enumerate(files):
            for file2 in files[i+1:]:
                if self._are_similar_names(
                    self.file_database[file1]['base_name'],
                    self.file_database[file2]['base_name']
                ):
                    # Only compare files of same size
                    if self.file_database[file1]['size'] == self.file_database[file2]['size']:
                        pairs.append((file1, file2))
        return pairs
    
    def _are_similar_names(self, name1, name2):
        base1 = name1
        base2 = name2
        return (base1 in base2 or base2 in base1) and name1 != name2
    
    def _get_file_hash(self, filepath):
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:  # Opens file in binary mode
                for byte_block in iter(lambda: f.read(4096), b""):  # Reads 4KB chunks
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except PermissionError:
            raise PermissionError(f"No permission to read file: {filepath}")
        except IOError as e:
            raise IOError(f"Error reading file {filepath}: {str(e)}")
    
    def compare_files(self, file1, file2):
        # First quick check: compare file sizes
        if os.path.getsize(file1) != os.path.getsize(file2):
            return False
        # Then do full binary comparison via hashing
        return self._get_file_hash(file1) == self._get_file_hash(file2)
    
    def process_duplicates(self, progress_callback=None):
        self.update_progress = progress_callback or (lambda x: None)
        
        # First phase: Scan directories
        total_files = self.scan_directory()
        if total_files == 0:
            return "No files found in source directory"

        self.update_status("Scanning complete. Processing duplicates...")
        
        # Second phase: Process duplicates
        pairs = self.get_file_pairs()
        processed_count = 0
        failed_count = 0
        total_pairs = len(pairs)
        
        for idx, (file1, file2) in enumerate(pairs):
            try:
                source_path = self.file_database[file2]['full_path']
                if not os.path.exists(source_path):
                    self.update_status(f"Warning: Source file no longer exists: {source_path}")
                    continue

                if self.compare_files(
                    self.file_database[file1]['full_path'],
                    source_path
                ):
                    # Normalize destination path
                    dest_path = os.path.normpath(os.path.join(
                        self.destination_dir, 
                        file2
                    )).replace('\\', '/')
                    
                    # Create subdirectories in destination if needed
                    dest_dir = os.path.dirname(dest_path)
                    os.makedirs(dest_dir, exist_ok=True)
                    
                    self.update_status(f"Moving: {source_path} -> {dest_path}")
                    
                    # Double-check files exist before operation
                    if os.path.exists(source_path):
                        os.rename(source_path, dest_path)
                        processed_count += 1
                    else:
                        raise FileNotFoundError(f"Source file disappeared: {source_path}")
                
                # Update progress (50-100% for comparing/moving)
                progress = 50 + ((idx + 1) / total_pairs) * 50
                self.update_progress(progress)
                
            except (PermissionError, OSError) as e:
                self.failed_operations.append((file2, str(e)))
                failed_count += 1
                continue
        
        # Prepare summary message
        summary = []
        summary.append(f"Scanned {total_files} files in total")
        if processed_count > 0:
            summary.append(f"Successfully moved {processed_count} duplicate files")
        if failed_count > 0:
            summary.append(f"Failed to process {failed_count} files")
            for file, error in self.failed_operations:
                summary.append(f"- {file}: {error}")
        
        return "\n".join(summary) if summary else "No duplicate files found"

# Define the DuplicateFinderGUI class
class DuplicateFinderGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Duplicate File Finder")
        self.root.geometry("600x500")
        
        self.create_widgets()
    
    def create_widgets(self):
        # Source directory
        source_frame = ttk.LabelFrame(self.root, text="Source Directory", padding="5")
        source_frame.pack(fill="x", padx=5, pady=5)
        
        self.source_path = ttk.Entry(source_frame, width=50)
        self.source_path.pack(side="left", padx=5)
        ttk.Button(source_frame, text="Browse", command=self.browse_source).pack(side="left", padx=5)
        
        # Destination directory
        dest_frame = ttk.LabelFrame(self.root, text="Destination Directory", padding="5")
        dest_frame.pack(fill="x", padx=5, pady=5)
        
        self.dest_path = ttk.Entry(dest_frame, width=50)
        self.dest_path.pack(side="left", padx=5)
        ttk.Button(dest_frame, text="Browse", command=self.browse_dest).pack(side="left", padx=5)
        
        # Status display
        status_frame = ttk.LabelFrame(self.root, text="Status", padding="5")
        status_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(status_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.status_text = tk.Text(status_frame, height=10, width=50, wrap="word", yscrollcommand=scrollbar.set)
        self.status_text.pack(fill="both", expand=True, padx=5, pady=5)
        scrollbar.config(command=self.status_text.yview)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()  # Fixed: Using tk.DoubleVar instead of ttk.DoubleVar
        self.progress = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100)
        self.progress.pack(fill="x", padx=5, pady=5)
        
        # Start button
        self.start_button = ttk.Button(self.root, text="Start Scanning", command=self.start_scanning)
        self.start_button.pack(pady=10)
    
    def browse_source(self):
        directory = filedialog.askdirectory()
        if directory:
            self.source_path.delete(0, "end")
            self.source_path.insert(0, directory)
    
    def browse_dest(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dest_path.delete(0, "end")
            self.dest_path.insert(0, directory)
    
    def update_status(self, message):
        self.status_text.insert("end", message + "\n")
        self.status_text.see("end")
    
    def start_scanning(self):
        self.source = self.source_path.get()
        self.dest = self.dest_path.get()
        
        if not self.source or not self.dest:
            messagebox.showerror("Error", "Please select both source and destination directories")
            return
        
        if not os.path.exists(self.source):
            messagebox.showerror("Error", "Source directory does not exist")
            return
        
        if not os.path.exists(self.dest):
            try:
                os.makedirs(self.dest)
            except Exception as e:
                messagebox.showerror("Error", f"Could not create destination directory: {e}")
                return
        
        self.start_button.config(state="disabled")
        self.status_text.delete(1.0, "end")
        self.update_status("Starting scan...")
        
        def scan_thread():
            try:
                comparator = FileComparator(
                    self.source, 
                    self.dest,
                    status_callback=self.update_status
                )
                result = comparator.process_duplicates(
                    progress_callback=lambda x: self.progress_var.set(x)
                )
                self.update_status(result)
            except Exception as e:
                self.update_status(f"Error: {str(e)}")
                messagebox.showerror("Error", str(e))
            finally:
                self.progress_var.set(0)
                self.start_button.config(state="normal")
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def run(self):
        self.root.mainloop()

# Define the main function
def main():
    app = DuplicateFinderGUI()
    app.run()

# Run the main function
if __name__ == "__main__":
    main()
