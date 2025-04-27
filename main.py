import sys
import psutil
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import csv
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
from matplotlib.animation import FuncAnimation

class SecurityLogger:
    def __init__(self, root):
        self.root = root
        self.root.title("Real Time Process Monitoring System")
        self.root.geometry("1400x900")  # Increased window size
        
        # Initialize variables
        self.logs = []
        self.process_history = defaultdict(list)
        self.anomaly_threshold = 5  # Threshold for anomaly detection
        
        # Initialize graph data with numpy arrays for better performance
        self.max_data_points = 60
        self.time_data = np.zeros(self.max_data_points, dtype=object)
        self.cpu_data = np.zeros(self.max_data_points)
        self.memory_data = np.zeros(self.max_data_points)
        self.data_index = 0
        
        # Configure modern color scheme
        self.colors = {
            'bg': '#1E1E1E',
            'fg': '#FFFFFF',
            'accent': '#00FF9D',
            'warning': '#FF6B6B',
            'info': '#4ECDC4',
            'graph_bg': '#2D2D2D',
            'grid': '#404040',
            'process_bg': '#2A2A2A'
        }
        
        # Configure dark theme with new colors
        self.root.configure(bg=self.colors['bg'])
        style = ttk.Style()
        style.configure("Dark.TFrame", background=self.colors['bg'])
        style.configure("Dark.TLabel", background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure("Dark.TButton", background=self.colors['bg'], foreground=self.colors['fg'])
        style.configure("Dark.TCombobox", background=self.colors['bg'], foreground=self.colors['fg'])
        
        # Configure style for combobox with white background and black text
        style.configure("WhiteBlack.TCombobox",
                       fieldbackground='#FFFFFF',  # White background
                       background='#FFFFFF',      # White background for dropdown
                       foreground='#000000',      # Black text
                       arrowcolor='#000000',      # Black arrow
                       selectbackground='#000000',  # Black selection background
                       selectforeground='#FFFFFF')  # White selection text
        
        # Create main frame
        main_frame = ttk.Frame(root, style="Dark.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create header with accent color
        header = ttk.Label(main_frame, text="Real Time Process Monitoring System", 
                          font=('Arial', 16, 'bold'), foreground=self.colors['accent'],
                          style="Dark.TLabel")
        header.pack(pady=10)
        
        # Create control panel
        control_frame = ttk.Frame(main_frame, style="Dark.TFrame")
        control_frame.pack(fill=tk.X, pady=5)
        
        # Filter dropdown with accent color
        ttk.Label(control_frame, text="Filter:", foreground=self.colors['accent'],
                 style="Dark.TLabel").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar(value="All Events")
        
        filter_combo = ttk.Combobox(control_frame, textvariable=self.filter_var, 
                                  values=["All Events", "Process Events", "Resource Usage", "Security Alerts"],
                                  state="readonly", style="WhiteBlack.TCombobox")
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.bind('<<ComboboxSelected>>', self.filter_logs)
        
        # Configure colors for the dropdown list
        self.root.option_add('*TCombobox*Listbox.background', '#FFFFFF')  # White background for list
        self.root.option_add('*TCombobox*Listbox.foreground', '#000000')  # Black text for list
        self.root.option_add('*TCombobox*Listbox.selectBackground', '#000000')  # Black selection background
        self.root.option_add('*TCombobox*Listbox.selectForeground', '#FFFFFF')  # White selection text
        
        # Export button with white background and black text
        export_btn = ttk.Button(control_frame, text="Export Logs", 
                               command=self.export_logs, style="WhiteBlack.TButton")
        export_btn.pack(side=tk.LEFT, padx=5)
        
        # Configure style for the export button
        style.configure("WhiteBlack.TButton",
                        background='#FFFFFF',  # White background
                        foreground='#000000')  # Black text
        
        # Clear button with white background and black text
        clear_btn = ttk.Button(control_frame, text="Clear Logs", 
                              command=self.clear_logs, style="WhiteBlack.TButton")
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Configure style for the buttons
        style.configure("WhiteBlack.TButton",
                        background='#FFFFFF',  # White background
                        foreground='#000000')  # Black text
        
        # Create graphs frame
        graphs_frame = ttk.Frame(main_frame, style="Dark.TFrame")
        graphs_frame.pack(fill=tk.X, pady=5)
        
        # Create CPU usage graph with improved performance
        self.cpu_fig = Figure(figsize=(6, 3), facecolor=self.colors['graph_bg'])
        self.cpu_ax = self.cpu_fig.add_subplot(111)
        self.cpu_ax.set_facecolor(self.colors['graph_bg'])
        self.cpu_canvas = FigureCanvasTkAgg(self.cpu_fig, master=graphs_frame)
        self.cpu_canvas.get_tk_widget().pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Create Memory usage graph with improved performance
        self.memory_fig = Figure(figsize=(6, 3), facecolor=self.colors['graph_bg'])
        self.memory_ax = self.memory_fig.add_subplot(111)
        self.memory_ax.set_facecolor(self.colors['graph_bg'])
        self.memory_canvas = FigureCanvasTkAgg(self.memory_fig, master=graphs_frame)
        self.memory_canvas.get_tk_widget().pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Configure graphs
        self.setup_graphs()
        
        # Create process list frame
        process_frame = ttk.Frame(main_frame, style="Dark.TFrame")
        process_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create process list header
        process_header = ttk.Label(process_frame, text="Running Processes", 
                                 font=('Arial', 12, 'bold'), foreground=self.colors['accent'],
                                 style="Dark.TLabel")
        process_header.pack(pady=5)
        
        # Create process list with columns
        self.process_tree = ttk.Treeview(process_frame, columns=('PID', 'Name', 'CPU%', 'Memory%', 'Status'),
                                        show='headings', style="Dark.Treeview")
        
        # Configure columns
        self.process_tree.heading('PID', text='PID')
        self.process_tree.heading('Name', text='Process Name')
        self.process_tree.heading('CPU%', text='CPU %')
        self.process_tree.heading('Memory%', text='Memory %')
        self.process_tree.heading('Status', text='Status')
        
        # Set column widths
        self.process_tree.column('PID', width=80)
        self.process_tree.column('Name', width=200)
        self.process_tree.column('CPU%', width=80)
        self.process_tree.column('Memory%', width=80)
        self.process_tree.column('Status', width=100)
        
        # Add scrollbar
        process_scrollbar = ttk.Scrollbar(process_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=process_scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        process_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Create log display with improved colors
        self.log_display = scrolledtext.ScrolledText(main_frame, height=15, 
                                                    bg=self.colors['graph_bg'], fg=self.colors['fg'],
                                                    font=('Consolas', 10))
        self.log_display.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create status bar with info color
        self.status_var = tk.StringVar(value="Monitoring system events...")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              foreground=self.colors['info'], style="Dark.TLabel")
        status_bar.pack(fill=tk.X, pady=5)
        
        # Start monitoring with optimized update interval
        self.monitor_system()
    
    def setup_graphs(self):
        # Configure CPU graph with improved colors
        self.cpu_ax.set_title('CPU Usage (%)', color=self.colors['accent'])
        self.cpu_ax.set_ylim(0, 100)
        self.cpu_ax.set_xlim(0, self.max_data_points)
        self.cpu_ax.tick_params(colors=self.colors['fg'])
        self.cpu_ax.grid(True, color=self.colors['grid'])
        self.cpu_line, = self.cpu_ax.plot([], [], color=self.colors['accent'], label='CPU')
        
        # Configure Memory graph with improved colors
        self.memory_ax.set_title('Memory Usage (%)', color=self.colors['accent'])
        self.memory_ax.set_ylim(0, 100)
        self.memory_ax.set_xlim(0, self.max_data_points)
        self.memory_ax.tick_params(colors=self.colors['fg'])
        self.memory_ax.grid(True, color=self.colors['grid'])
        self.memory_line, = self.memory_ax.plot([], [], color=self.colors['info'], label='Memory')
        
        # Update graphs
        self.cpu_canvas.draw()
        self.memory_canvas.draw()
    
    def update_graphs(self):
        current_time = datetime.now()
        cpu_percent = psutil.cpu_percent()
        memory_percent = psutil.virtual_memory().percent
        
        # Update data arrays using numpy for better performance
        self.time_data[self.data_index] = current_time
        self.cpu_data[self.data_index] = cpu_percent
        self.memory_data[self.data_index] = memory_percent
        
        # Update index with wrap-around
        self.data_index = (self.data_index + 1) % self.max_data_points
        
        # Update CPU graph
        self.cpu_line.set_data(range(self.max_data_points), self.cpu_data)
        self.cpu_ax.relim()
        self.cpu_ax.autoscale_view()
        self.cpu_canvas.draw_idle()  # Use draw_idle for better performance
        
        # Update Memory graph
        self.memory_line.set_data(range(self.max_data_points), self.memory_data)
        self.memory_ax.relim()
        self.memory_ax.autoscale_view()
        self.memory_canvas.draw_idle()  # Use draw_idle for better performance
        
    def update_process_list(self):
        # Clear existing items
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        # Get current processes
        processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']))
        
        # Sort processes by CPU usage
        processes.sort(key=lambda x: x.info['cpu_percent'] or 0, reverse=True)
        
        # Add processes to treeview
        for proc in processes:
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                cpu_percent = proc.info['cpu_percent'] or 0
                memory_percent = proc.info['memory_percent'] or 0
                status = proc.info['status']
                
                # Format values
                cpu_str = f"{cpu_percent:.1f}%"
                memory_str = f"{memory_percent:.1f}%"
                
                # Add to treeview
                self.process_tree.insert('', 'end', values=(pid, name, cpu_str, memory_str, status))
                
                # Highlight high CPU usage processes
                if cpu_percent > 80:
                    item = self.process_tree.get_children()[-1]
                    self.process_tree.tag_configure('high_cpu', foreground=self.colors['warning'])
                    self.process_tree.item(item, tags=('high_cpu',))
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    
    def monitor_system(self):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Update graphs
            self.update_graphs()
            
            # Update process list
            self.update_process_list()
            
            # Monitor processes with optimized batch processing
            processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))
            for proc in processes:
                try:
                    name = proc.info['name']
                    cpu_percent = proc.info['cpu_percent'] or 0
                    memory_percent = proc.info['memory_percent'] or 0
                    pid = proc.info['pid']
                    
                    if name not in self.process_history:
                        self.process_history[name] = []
                    
                    self.process_history[name].append({
                        'time': current_time,
                        'cpu': cpu_percent,
                        'memory': memory_percent
                    })
                    
                    # Detect anomalies with optimized threshold checking
                    if len(self.process_history[name]) > self.anomaly_threshold:
                        recent_usage = [p['cpu'] for p in self.process_history[name][-self.anomaly_threshold:]]
                        if max(recent_usage) > 80:  # High CPU usage
                            self.log_event(f"⚠️ High CPU usage detected for {name} (PID: {pid})", 'warning')
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Monitor system resources
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            
            if cpu_percent > 80 or memory_percent > 80:
                self.log_event(f"⚠️ High resource usage detected (CPU: {cpu_percent}%, Memory: {memory_percent}%)", 'warning')
        
        except Exception as e:
            self.log_event(f"❌ Error monitoring system: {str(e)}", 'error')
        
        # Schedule next update with optimized interval
        self.root.after(500, self.monitor_system)  # Reduced to 500ms for faster updates
    
    def log_event(self, event, level='info'):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {event}"
        self.logs.append(log_entry)
        
        # Color coding for different event types
        if level == 'warning':
            self.log_display.insert(tk.END, log_entry + '\n', 'warning')
            self.log_display.tag_configure('warning', foreground=self.colors['warning'])
        elif level == 'error':
            self.log_display.insert(tk.END, log_entry + '\n', 'error')
            self.log_display.tag_configure('error', foreground=self.colors['warning'])
        else:
            self.log_display.insert(tk.END, log_entry + '\n')
        
        self.log_display.see(tk.END)
    
    def filter_logs(self, event=None):
        self.log_display.delete('1.0', tk.END)
        filter_text = self.filter_var.get()
        
        # Configure tag colors for different event types
        self.log_display.tag_configure('process', foreground=self.colors['accent'])
        self.log_display.tag_configure('resource', foreground=self.colors['info'])
        self.log_display.tag_configure('security', foreground=self.colors['warning'])
        
        for log in self.logs:
            if filter_text == "All Events":
                if "Process" in log:
                    self.log_display.insert(tk.END, log + '\n', 'process')
                elif "resource" in log.lower():
                    self.log_display.insert(tk.END, log + '\n', 'resource')
                elif "Security Alert" in log:
                    self.log_display.insert(tk.END, log + '\n', 'security')
                else:
                    self.log_display.insert(tk.END, log + '\n')
            elif filter_text == "Process Events" and "Process" in log:
                self.log_display.insert(tk.END, log + '\n', 'process')
            elif filter_text == "Resource Usage" and "resource" in log.lower():
                self.log_display.insert(tk.END, log + '\n', 'resource')
            elif filter_text == "Security Alerts" and "Security Alert" in log:
                self.log_display.insert(tk.END, log + '\n', 'security')
    
    def export_logs(self):
        file_name = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Export Logs"
        )
        if file_name:
            try:
                with open(file_name, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(['Timestamp', 'Event'])
                    for log in self.logs:
                        timestamp = log[1:20]  # Extract timestamp
                        event = log[22:]  # Extract event message
                        writer.writerow([timestamp, event])
                messagebox.showinfo("Success", "Logs exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {str(e)}")
    
    def clear_logs(self):
        self.logs.clear()
        self.log_display.delete('1.0', tk.END)
        self.process_history.clear()
        self.cpu_data.fill(0)
        self.memory_data.fill(0)
        self.time_data.fill(None)
        self.data_index = 0
        self.status_var.set("Logs cleared")

if __name__ == '__main__':
    root = tk.Tk()
    app = SecurityLogger(root)
    root.mainloop()
