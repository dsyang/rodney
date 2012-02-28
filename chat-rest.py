#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
'Rodney' : Your personal secretary for facebook chat
"""

import sys
import time
import logging
from getpass import getpass
import argparse

from pyxmpp2.jid import JID
from pyxmpp2.message import Message
from pyxmpp2.presence import Presence
from pyxmpp2.client import Client
from pyxmpp2.settings import XMPPSettings
from pyxmpp2.interfaces import EventHandler, event_handler, QUIT
from pyxmpp2.streamevents import AuthorizedEvent, DisconnectedEvent
from pyxmpp2.roster import RosterReceivedEvent, RosterUpdatedEvent
from pyxmpp2.interfaces import XMPPFeatureHandler
from pyxmpp2.interfaces import presence_stanza_handler, message_stanza_handler
from pyxmpp2.ext.version import VersionProvider

from urllib2 import quote, unquote
import ttp
import twilio

from datetime import date, timedelta
import rfc3339 as rfc
import random


def get_facebook_client():
    """
    Using the pyfacebook library.  It actually uses the
     old facebook api (I think), unfortunately changing to access
     token authentication didn't work.  The code I wrote for that is
     available on request
    """
    import facebook

    api_key = 'FILL_THIS_IN'
    secret_key = 'FILL_THIS_IN'

    client = facebook.Facebook(api_key, secret_key)

    try:
        # Try to read cached credentials from the session-key file.
        # If authorization fails, you should delete this file and start of.
        handle = open('session-key', 'r')
        client.uid, client.session_key, client.secret = [ line.strip() for line in handle ]
        handle.close()
    except IOError:
        client.auth.createToken()
        client.login()
        print 'Log in to the app in your browser, then press enter.'
        raw_input()
        client.auth.getSession()
        handle = open('session-key', 'w')
        print >> handle, client.uid
        print >> handle, client.session_key
        print >> handle, client.secret
        handle.close()



    if not int(client.users.hasAppPermission('xmpp_login')):
        import webbrowser
        webbrowser.open(client.get_url('authorize',
                ext_perm = 'xmpp_login',
                api_key = client.api_key,
                v = '1.0'))
        print 'Grant the extended permission to the app in your browser, then press enter.'
        raw_input()

    return client



def get_gcal_events():
    """
    Authenticates with google apis and uses the v3 calendar api to grab your
    events 24 hours before and after the current time. This is done ahead of
    time so Rodney wouldn't have to check every message.
    """
    import httplib2
    from apiclient.discovery import build
    from oauth2client.file import Storage
    from oauth2client.client import AccessTokenRefreshError
    from oauth2client.client import OAuth2WebServerFlow
    from oauth2client.tools import run

    FLOW = OAuth2WebServerFlow(
        client_id='FILL_THIS_IN',
        client_secret='FILL_THIS_IN',
        scope='https://www.googleapis.com/auth/calendar.readonly',
        user_agent='rodney-gcal/1.0')

    storage = Storage('gcal.dat')
    credentials = storage.get()

    if credentials is None or credentials.invalid == True:
        credentials = run(FLOW, storage)

    http = httplib2.Http(cache=".cache")
    http = credentials.authorize(http)

    service = build("calendar", "v3", http=http)

    yesterday = rfc.datetimetostr(rfc.now() - timedelta(1))
    tomorrow = rfc.datetimetostr(rfc.now() + timedelta(1))

    events = service.events().list(calendarId='primary', timeMin=yesterday, timeMax=tomorrow, orderBy='startTime', singleEvents=True).execute()

    try:
        print "Found {0} events between {1} and {2}".format(len(events['items']), yesterday, tomorrow)
    except KeyError:
        print "no events"
        return []


    return events['items']



from pyxmpp2.sasl.core import sasl_mechanism
from pyxmpp2.sasl.core import ClientAuthenticator, Response, Failure, Success
@sasl_mechanism("X-FACEBOOK-PLATFORM", True)
class XFacebookPlatformClientAuthenticator(ClientAuthenticator):
    """
    This is what implements the facebook X-FACEBOOK-PLATFORM auth for xmpp.
    It actually works!! But is largely taken from the examples on the net.
    it uses a global facebook client (see __init__)
    """

    def __init__(self, fb_client=None):
        ClientAuthenticator.__init__(self)
        if fb_client is None:
            global global_fb_client
            fb_client = global_fb_client
        self._fb_client = fb_client


    def start(self, ignored_properties):
        return Response(None)

    def challenge(self, challenge):
        in_params = dict([part.split('=') for part in challenge.split('&')])

        out_params = {'nonce': in_params['nonce']}
        out_params = self._fb_client._add_session_args(out_params)
        out_params = self._fb_client._build_post_args(in_params['method'], out_params)
        import urllib
        return Response(urllib.urlencode(out_params))

    def finish(self,data):
        return Success(None)

    @classmethod
    def are_properties_sufficient(self, properties):
            return "username" in properties and "service-domain" in properties and properties['service-domain'] == "chat.facebook.com"



def send_text(text, sender):
    """
    Twilio code.  You'll need to get an account on twilio for this.
    fortunately twilio offers free accounts :)

    inputs:
    'text' : string = text of message to send
    'sender' : string = the name of whoever wanted to send the text.

    output : string = the text message body sent

    """
    from twilio.rest import TwilioRestClient

    account = "FILL_THIS_IN"
    token = "FILL_THIS_IN"
    client = TwilioRestClient(account, token)
    print "sending text"
    body="Hi, {0} wants to say: {1}".format(sender, text)
    message = client.sms.messages.create(to="", from_="",
                                         body=body)
    print "sent text"
    return body


def check_gcal(event_items):
    """
    Given a bunch of events from gcal,
    It looks at the time now and finds if it intersects any current events
    If it does it says you're free at the end of the event, so it will not
    be accurate if you have 2 back-to-back events.

    input:
    'event_items' : list = events grabbed by rodney at the beginning.

    output : string =  the string that gets sent by rodney over fbchat
    """
    now = int(time.time())
    yesterday = rfc.datetimetostr(rfc.now() - timedelta(1))
    tomorrow = rfc.datetimetostr(rfc.now() + timedelta(1))
    busy = False
    times = []

    for event in event_items:
        estartts = rfc.strtotimestamp(event['start']['dateTime'])
        eendts =  rfc.strtotimestamp(event['end']['dateTime'])
        if estartts < now < eendts:
            busy = True
        times.append(estartts)
        times.append(eendts)
    print times
    print busy
    print now
    if not busy:
        return "{0} should be free right now (according to gcal)"
    else:
        msg = "{0} is busy right now. He will be free..."
        free = zip(times[::2], times[1::2])
        freestr = []
        for (s,e) in free:
            if s < now < e:
                estr = time.strftime("%I:%M%p", time.localtime(e))
                freestr.append("after {0}.\n".format(estr))
        if len(freestr) == 0:
            msg += "Never :( try sending a text"
        else:
            msg += (' '.join(freestr))
        return msg

def lolz(intext):
    """
    the misc function, where all the jokes are. The jokes just look for keywords
    in the chat received and do something fun.

    inputs:
    'intext' : string = message that rodney received

    output : string = string that gets sent by rodney
    """

    text = intext.lower()
    stuff = ['http://dynamic.xkcd.com/random/comic/', 'http://icanhascheezburger.com/?random',
             'http://www.fortunecookiemessage.com/', ]

    if 'sandwich' in text and 'make' in text or "make me a sandwich" == text:
        if 'sudo' in text:
            return "Of course, right away!"
	else:
	    return "NO I WILL NOT MAKE A SANDWICH!!"
    elif 'asdf' in text or "lkj" in text:
        return text+text
    elif 'rodney' in text and ('how are you' in text or "doing" in text):
        return intext+"? "+"Thanks for asking! I'm pretty bored actually..."
    else:
        random.seed(time.time())
        link = random.choice(stuff)
        return "I don't understand, have a random funny instead! {0}".format(link)


class Rodney(EventHandler, XMPPFeatureHandler):
    """Personal Secretary for facebook chat."""
    def __init__(self, my_jid, settings, myname, events, text):
        version_provider = VersionProvider(settings)
        self.client = Client(my_jid, [self, version_provider], settings)
        self.myname = myname #first and last name of user
        self.logs = {}
        self.parser = ttp.Parser() #twitter text processing lib handler
        self.events = events
        self.do_text = text
        self.last_msg = ""

    def run(self):
        """Request client connection and start the main loop."""
        self.client.connect()
        self.client.run()

    def disconnect(self):
        """Request disconnection and let the main loop run for a 2 more
        seconds for graceful disconnection."""
        self.client.disconnect()
        self.client.run(timeout = 2)

    @presence_stanza_handler("subscribe")
    def handle_presence_subscribe(self, stanza):
        logging.info(u"{0} requested presence subscription"
                                                    .format(stanza.from_jid))
        presence = Presence(to_jid = stanza.from_jid.bare(),
                                                    stanza_type = "subscribe")
        return [stanza.make_accept_response(), presence]

    @presence_stanza_handler("subscribed")
    def handle_presence_subscribed(self, stanza):
        logging.info(u"{0!r} accepted our subscription request"
                                                    .format(stanza.from_jid))
        return True

    @presence_stanza_handler("unsubscribe")
    def handle_presence_unsubscribe(self, stanza):
        logging.info(u"{0} canceled presence subscription"
                                                    .format(stanza.from_jid))
        presence = Presence(to_jid = stanza.from_jid.bare(),
                                                    stanza_type = "unsubscribe")
        return [stanza.make_accept_response(), presence]

    @presence_stanza_handler("unsubscribed")
    def handle_presence_unsubscribed(self, stanza):
        logging.info(u"{0!r} acknowledged our subscrption cancelation"
                                                    .format(stanza.from_jid))
        return True

    @event_handler(DisconnectedEvent)
    def handle_disconnected(self, event):
        endtime= int(time.time())
        filename = "rodney.{0}.log".format(endtime)
        f = open(filename, "w")
        from pprint import PrettyPrinter
        pp = PrettyPrinter(depth=10, stream=f)
        pp.pprint(self.logs)
        print "My transcript has been written to {0}".format(filename)
        """Quit the main loop upon disconnection."""
        return QUIT

    @event_handler()
    def handle_all(self, event):
        """Log all events."""
        logging.info(u"-- {0}".format(event))


    @event_handler(RosterReceivedEvent)
    def handle_roster_received(self, event):
        self.roster_items = self.client.roster.items()
        print type(self.roster_items)
        print "Roster received!"

    @message_stanza_handler()
    def handle_message(self, stanza):
        """ Does message dispatching:
        1) Checks when you're free on calendar
        2) Sends you a text
        3) Playful responses
        """
        if stanza.body is None:
            print stanza
        elif stanza.body == self.last_msg:
            print "bad"
            return
        else:
            self.last_msg = stanza.body
            parsed = self.parser.parse(stanza.body)

            sender = (i for i in self.roster_items if i.jid == stanza.from_jid ).next()
            if sender.name not in self.logs.keys():
                self.logs[sender.name] = []


            if sender == None:
                print "no name found, making it fuzz"
                name = "fuzz"
            else:
                name = sender.name
            print "{0} sent the message: {1}".format(name, stanza.body)

            inmsg = stanza.body.lower()
            if len(self.logs[name]) == 0 or 'help' in parsed.tags:
                res = ' '.join(["Hi there! I'm Rodney, the personal fbchat secretary. {0}'s not around right now, can I help you with anything?".format(self.myname),
                                "\n 1) When is he free? (the question or '#free')",
                                "\n 2) Text him. ('#text message')",
                                "\n 3) #random",
                                "#help"])
            else:
                if 'free' in parsed.tags or ("when" in inmsg and "free" in inmsg):
                    res = ' '.join([word for word in stanza.body.split() if not word == '#free'])
                    res += "?\n"
                    res +=  check_gcal(self.events).format(self.myname.split()[0])
                elif 'text' in parsed.tags:
                    if not self.do_text:
                        res = "Sorry, texting is disabled for now ({0} is really cheap!)".format(self.myname.split()[0])
                    elif inmsg.strip() == '#text':
                        res = "Don't send an empty message! The texting costs come out of my salary :("
                    else:
                        out = ' '.join([w for w in stanza.body.split() if not w == '#text'])
                        outmsg = send_text(out, name)
                        res = "Ok! I sent the message: {0} to {1}".format(outmsg, self.myname.split()[0])
                elif 'random' in parsed.tags:
                    # corpus from nltk
                    res = "coming soon...."
                else:
                    res = lolz(stanza.body)



            msg = Message(stanza_type = stanza.stanza_type,
                          from_jid = stanza.to_jid, to_jid = stanza.from_jid,
                          body = res,thread = stanza.thread)


            self.logs[name].append(time.asctime() + " {0}: ".format(name) + stanza.body)
            self.logs[name].append(time.asctime() + " {0}: ".format(self.myname) + res)

            return msg

def main(myname, events):
    """Parse the command-line arguments and run the bot."""

    parser = argparse.ArgumentParser(description= "Rodney: your personal fbchat secretary")


    parser.add_argument('username', help='who you want Rodney to log in as.')
    parser.add_argument('-t', '--text', action='store_const', const=True, default=False)
    parser.add_argument('-d','--debug', action='store_const', const=True, default=False)

    passed_args = parser.parse_args()
    username = passed_args.username

    settings = XMPPSettings({
        "software_name": "Rodney",
        "server": "chat.facebook.com",
        "tls_require" : False,
        "starttls" : False,
        "prefer_ipv6" : True,
        "tls_verify_peer" : True,
        "tls_cacert_file" : False,
        "ipv6" : None,
        "c2s_port" : 5222,
        "sasl_mechanisms" : ["X-FACEBOOK-PLATFORM"],
        "insecure_auth" : True

    })

    user_logs = {}

    if passed_args.debug:# True:
        print "enabling trace"
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        for logger in ("pyxmpp2.IN", "pyxmpp2.OUT"):
            logger = logging.getLogger(logger)
            logger.setLevel(logging.DEBUG)
            logger.addHandler(handler)
            logger.propagate = False

    print "connecting..."
    bot = Rodney(JID(username), settings, myname, events, passed_args.text)
    print "connected"
    try:
        bot.run()
    except KeyboardInterrupt:
        bot.disconnect()

if __name__ == '__main__':
    print "Preparing Facebook Client..."
    global_fb_client = get_facebook_client()
    myname = global_fb_client.users.getInfo(global_fb_client.uid, ['name'])[0]['name']
    print "Setting up gcal"
    cal_events = get_gcal_events()

    main(myname, cal_events)
