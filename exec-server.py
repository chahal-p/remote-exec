#!/usr/bin/env python3

import http.server
import socketserver
import subprocess
import traceback
import threading
import time
from queue import Queue, Empty as EmptyQueueError

PORT = 5567

def reader(pipe, queue: Queue, type: str, done: threading.Event, cancelled: threading.Event):
  with pipe:
    for line in iter(pipe.readline, b''):
      if cancelled.is_set():
        break
      hex_output = line.hex()
      queue.put(f"{type}:{hex_output}\n".encode('utf-8'))
  done.set()

def output_reader(stdout, stderr, cancelled: threading.Event):
  queue = Queue()
  done_stdout = threading.Event()
  done_stderr = threading.Event()
  t1 = threading.Thread(target=reader, args=[stdout, queue, 'STDOUT', done_stdout, cancelled])
  t2 = threading.Thread(target=reader, args=[stderr, queue, 'STDERR', done_stderr, cancelled])
  t1.start()
  t2.start()
  while not done_stdout.is_set() or not done_stderr.is_set():
    try:
      yield queue.get(timeout=0.1)
    except EmptyQueueError:
      pass

def kill_process_if_cancelled(process: subprocess.Popen, cancelled: threading.Event):
  def checker():
    while True:
      if process.returncode is not None:
        break
      if cancelled.is_set():
        process.kill()
      time.sleep(1)
  threading.Thread(target=checker).start()

class HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
  def run(self, cmd: list, cancelled: threading.Event):
    try:
      process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      kill_process_if_cancelled(process, cancelled)
      for l in output_reader(process.stdout, process.stderr, cancelled):
        yield l
      for _ in range(10):
        try:
          process.wait(1)
          break
        except subprocess.TimeoutExpired:
          pass
      hex_code = str(process.returncode).encode('utf-8').hex()
      yield f"CODE:{hex_code}\n".encode('utf-8')
    except Exception as e:
      cancelled.set()
      traceback.print_exception(e)
      err_msg = str(e).encode('utf-8').hex()
      yield f"STDERR:{err_msg}\n".encode('utf-8')
      yield f"CODE:0x01\n".encode('utf-8')

  def watch_for_connection(self, cancelled: threading.Event):
    def checker():
      while True:
        if cancelled.is_set():
          break
        try:
          self.wfile.write('PING'.encode('utf-8'))
        except Exception as e:
          traceback.print_exception(e)
          cancelled.set()
          break
        time.sleep(5)
    threading.Thread(target=checker).start()

  def do_POST(self):
    self.connection
    cancelled = threading.Event()
    try:
      self.exec(cancelled)
      cancelled.set()
    except Exception as e:
      cancelled.set()
      traceback.print_exception(e)
      self.send_response(500)
      self.end_headers()
      self.wfile.write(b'')


  def exec(self, cancelled: threading.Event):
    try:
      content_length = int(self.headers['Content-Length'])
      if not content_length:
        raise ValueError("")
      post_data_hex = self.rfile.read(content_length).decode('utf-8')
      cmd = []
      for arg in post_data_hex.split(':'):
        cmd.append(bytes.fromhex(arg).decode('utf-8'))
      self.send_response(200)
      self.send_header('Content-Type', 'application/octet-stream')
      self.end_headers()
      self.watch_for_connection(cancelled)
      for l in self.run(cmd, cancelled):
        self.wfile.write(l)
    except ValueError as e:
      cancelled.set()
      traceback.print_exception(e)
      self.send_response(400)
      self.end_headers()
      self.wfile.write(b'')

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
  pass

if __name__ == "__main__":
  with ThreadedHTTPServer(("", PORT), HTTPRequestHandler) as server:
    print(f"Serving at port {PORT}")
    print("Server is running... Press Ctrl+C to stop.")
    server.serve_forever()
