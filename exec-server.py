#!/usr/bin/env python3

import argparse
import http.server
import os
import re
import socketserver
import subprocess
import traceback
import threading
import time
from queue import Queue, Empty as EmptyQueueError

FLAGS=None

PORT = 5567

class HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
  def run(self, cmd: list, cwd:str, cancelled: threading.Event):
    self.validate_cmd(' '.join(cmd))
    try:
      process = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
      cancelled.set()
      traceback.print_exception(e)
      yield stderr_line(str(e)), 1
    on_cancellation(cancelled, process.kill)
    for l in output_reader(process.stdout, process.stderr, cancelled):
      yield l, None
    for _ in range(10):
      try:
        process.wait(1)
        break
      except subprocess.TimeoutExpired:
        pass
    yield None, process.returncode

  def do_POST(self):
    cancelled = threading.Event()
    try:
      self.exec(cancelled)
      cancelled.set()
    except NotAllowedError as e:
      cancelled.set()
      traceback.print_exception(e)
      self.send_response(200)
      self.end_headers()
      self.wfile.write(stderr_line(str(e)))
      self.wfile.write(returncode_line(1))
    except Exception as e:
      cancelled.set()
      traceback.print_exception(e)
      self.send_response(500)
      self.end_headers()
      self.wfile.write(stderr_line('Internal Server Error'))
      self.wfile.write(returncode_line(1))

  def validate_cmd(self, cmd):
    if not FLAGS.allowed_commands:
      raise NotAllowedError(f'Command not Allowed: {cmd}')
    for rep in FLAGS.allowed_commands:
      reg = re.compile(rep)
      if reg.match(cmd):
        return
    raise NotAllowedError(f'Command not Allowed: {cmd}')

  def exec(self, cancelled: threading.Event):
    try:
      if 'Content-Length' not in self.headers:
        raise ValueError("Content-Length header not provided")
      clientaddr, _ = self.client_address
      if clientaddr != '127.0.0.1':
        raise NotAllowedError('exec server can only recieve request from 127.0.0.1')
      content_length = int(self.headers['Content-Length'])
      post_data_hex = self.rfile.read(content_length).decode('utf-8')
      cmd = []
      for arg in post_data_hex.split(':'):
        cmd.append(bytes.fromhex(arg).decode('utf-8'))
      self.send_response(200)
      self.send_header('Content-Type', 'application/octet-stream')
      self.end_headers()
      self.cancel_on_connection_closed(cancelled)
      cwd = FLAGS.exec_cwd
      cwd = self.headers.get('CWD', cwd)
      for line, code in self.run(cmd, cwd, cancelled):
        if line is not None:
          self.wfile.write(line)
        if code is not None:
          self.wfile.write(returncode_line(code))
    except ValueError as e:
      cancelled.set()
      traceback.print_exception(e)
      self.send_response(400)
      self.end_headers()
      self.wfile.write(stderr_line(str(e)))
      self.wfile.write(returncode_line(2))

  def cancel_on_connection_closed(self, cancelled: threading.Event):
    def checker():
      while True:
        if cancelled.is_set():
          break
        try:
          self.wfile.write('PING\n'.encode('utf-8'))
        except Exception as e:
          traceback.print_exception(e)
          cancelled.set()
          break
        time.sleep(5)
    threading.Thread(target=checker).start()


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
  pass


class NotAllowedError(Exception):
  pass


def hexstr(data: str|bytes|int):
  if isinstance(data, bytes):
    return bytes.hex(data)
  return bytes.hex(str(data).encode())

def output_line(type: str, line: str|bytes|int) -> bytes:
  return '{}:{}\n'.format(type, hexstr(line)).encode('utf-8')

def stdout_line(line: str|bytes) -> bytes:
  return output_line('STDOUT', line)

def stderr_line(line: str|bytes) -> bytes:
  return output_line('STDERR', line)

def returncode_line(code: int) -> bytes:
  return output_line('CODE', code)

def on_cancellation(cancelled: threading.Event, callback, *args, **kwargs):
  def checker():
    while True:
      if cancelled.is_set():
        callback(*args, **kwargs)
        break
      time.sleep(0.1)
  threading.Thread(target=checker).start()

def read_from_pipe(pipe, queue: Queue, type: str, done: threading.Event, cancelled: threading.Event):
  with pipe:
    for line in iter(pipe.readline, b''):
      if cancelled.is_set():
        break
      queue.put(output_line(type, line))
  done.set()

def output_reader(stdout, stderr, cancelled: threading.Event):
  queue = Queue()
  done_stdout = threading.Event()
  done_stderr = threading.Event()
  t1 = threading.Thread(target=read_from_pipe, args=[stdout, queue, 'STDOUT', done_stdout, cancelled])
  t2 = threading.Thread(target=read_from_pipe, args=[stderr, queue, 'STDERR', done_stderr, cancelled])
  t1.start()
  t2.start()
  while not queue.empty() or not done_stdout.is_set() or not done_stderr.is_set():
    try:
      yield queue.get(timeout=0.1)
    except EmptyQueueError:
      pass


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Exec server starts a http server to recieve commands and execute those.")
  parser.add_argument('-a', '--allowed-commands', action='append', metavar='', type=str, help="Regex pattern for allowed commands", default=[])
  parser.add_argument('-c', '--exec-cwd', metavar='', type=str, help="Default directory context", default=None)
  FLAGS = parser.parse_args()
  with ThreadedHTTPServer(("", PORT), HTTPRequestHandler) as server:
    print(f"Serving at port {PORT}")
    print("Server is running... Press Ctrl+C to stop.")
    server.serve_forever()
