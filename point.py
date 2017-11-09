#!/usr/bin/env python

"""
Point on a curve containing x and y coords because encryption
"""

class Point():
	def __init__(self, x, y):
		self.x = x
		self.y = y

	def __str__(self):
		return "Point(%s,%s)"%(self.x, self.y)

	def getX(self):
		return self.x

	def getY(self):
		return self.y

	#used when multiplying this by a scalar
	def __rmul__(self, other):
		return Point(self.x * other, self.y * other)
	
	def __mul__(self, other):
		return Point(self.x * other.x, self.y * other.y)

