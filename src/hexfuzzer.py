from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from burp import ITab
from javax.swing import JPanel,JCheckBox,JLabel,JSlider
from javax.swing.event import ChangeListener
from java.awt import BorderLayout,GridLayout,FlowLayout
from collections import namedtuple

EXTENSION_NAME = "Hex Fuzzer"
CUSTOM_TAB_NAME = "Hex Fuzzer"
GENERATED_PAYLOAD_NAME = "Hex Fuzzer"
OPTION_DESC = " Configure the extension-generated payloads here. Go to Intruder > Payloads and set the payload type to 'Hex Fuzzer'."
SLIDER_DESC = r" Use the slider below to control how many requests will be sent with each test case. E.g. setting this to 65 would test 0x00 to 0x41, \u0000 to \u0041 etc."

def gen_raw_hex(payload_range):
	return [chr(x) for x in range(payload_range)]

def gen_hex(payload_range):
	return [hex(x) for x in range(payload_range)]

def gen_hex_delim(payload_range):
	return [r'\x%s' % hex(x)[2:].rjust(2,'0') for x in range(payload_range)]

def gen_unicode_escaped(payload_range):
	return [r'\u00%s' % hex(x)[2:].rjust(2,'0') for x in range(payload_range)]

def gen_unicode_plus_escaped(payload_range):
	return [r'U+00%s' % hex(x)[2:].rjust(2,'0') for x in range(payload_range)]

def gen_unicode_percent_escaped(payload_range):
	return [r'%%u00%s' % hex(x)[2:].rjust(2,'0') for x in range(payload_range)]

def gen_unicode_es6_escaped(payload_range):
	return [r'\u{%s}' % hex(x)[2:].rjust(2,'0') for x in range(payload_range)]

def gen_octal_escaped(payload_range):
	return [r'\%s' % str(x).rjust(2,'0') for x in range(36, payload_range+36)] # Add 36 to the range here, aligning characters with other test cases.

def gen_url_encoded(payload_range):
	return ['%%%s' % hex(x)[2:].rjust(2,'0') for x in range(payload_range)]

def gen_html_encoded(payload_range):
	return ['&#x%s;' % hex(x)[2:].rjust(2,'0') for x in range(payload_range)]

def gen_all(payload_range):
	return [option.GenerateFunc(0x42)[0x41] for option in OPTIONS[:-1]] # All but the last option, which is this one. We hardcode the payload size as 0x42 here so we can show off the 'A' encodings as part of this test.

OPTION = namedtuple("OPTION",["UIElement","GenerateFunc"]) # Tuple for options => (UI Checkbox, Function to generate the payloads)

OPTIONS = [
	OPTION(JCheckBox("Raw Hex"), gen_raw_hex),
	OPTION(JCheckBox("'0x' Delimited (e.g. 0x41)"), gen_hex),
	OPTION(JCheckBox(r"'\x' Delimited (e.g. \x41)"), gen_hex_delim),
	OPTION(JCheckBox("Unicode Escaped (e.g. \\u0041)"), gen_unicode_escaped),
	OPTION(JCheckBox("Unicode Escaped (e.g. U+0041)"), gen_unicode_plus_escaped),
	OPTION(JCheckBox(r"Unicode Escaped (e.g. %u0041)"), gen_unicode_percent_escaped),
	OPTION(JCheckBox(r"ES6 Unicode Escaped (e.g. \u{41})"), gen_unicode_es6_escaped),
	OPTION(JCheckBox(r"Octal Escaped (e.g. \101)"), gen_octal_escaped),
	OPTION(JCheckBox("URL Encoded (e.g. %41)"), gen_url_encoded),
	OPTION(JCheckBox("HTML Encoded (e.g. &#x41;)"), gen_html_encoded),
	OPTION(JCheckBox(r"Quick Test of All The Above (e.g. 0x41, \x41, \u0041, ...)"), gen_all)
]

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, ITab):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		self.slider = None

		callbacks.registerIntruderPayloadGeneratorFactory(self)
		callbacks.setExtensionName(EXTENSION_NAME)
		callbacks.addSuiteTab(self)
		return

	def getTabCaption(self):
		return CUSTOM_TAB_NAME
	
	def getUiComponent(self):
		panel = JPanel(BorderLayout())
		check_panel = JPanel(GridLayout(20,0))
		panel.add(check_panel, BorderLayout.WEST)
		desc = JLabel(OPTION_DESC)
		check_panel.add(desc)
		for option in OPTIONS:
			check_panel.add(option.UIElement)
			option.UIElement.setSelected(1)

		slider_desc = JLabel(SLIDER_DESC)
		check_panel.add(slider_desc)
		self.slider = JSlider(1, 0x100) 
		self.slider.setMajorTickSpacing(15)
		self.slider.setPaintTicks(True)
		self.slider.setPaintLabels(True)
		self.slider.setVisible(True)
		check_panel.add(self.slider)
	
		return panel

	def getGeneratorName(self):
		return GENERATED_PAYLOAD_NAME

	def createNewInstance(self, attack):
		return HexFuzzer(self, attack, self.slider.getValue())
	
class HexFuzzer(IIntruderPayloadGenerator):
	def __init__(self, extender, attack, payload_range):
		self._extender = extender
		self._helpers = extender._helpers
		self._attack = attack
		self.numIterations = 0
		self.payloadList = []

		self.optionList = []
		for option in OPTIONS:
			if (option.UIElement.isSelected()):
				self.optionList += option.GenerateFunc(payload_range)

		self.maxPayloads = len(self.optionList)
		return

	def hasMorePayloads(self):
		return self.numIterations != self.maxPayloads

	def getNextPayload(self, currentPayload):
		payload = self.optionList[self.numIterations]
		self.numIterations += 1
		return payload

	def reset(self):
		self.maxPayloads = len(self.optionList)
		self.numIterations = 0
		self.payloadList = []
		return
