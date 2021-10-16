import os.path as op
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.utils import COMMASPACE, formatdate
from email import encoders
from email.mime.text import MIMEText
import smtplib

receiver = [""] #the receiver mail
list = open("list_of_mails.txt", "r")
lines = list.read().split()
for mail in lines:
    # print(line)
    # print(repr(line))
    sender = mail

    # list = open("list_of_mails.txt", "r")
    # for mail in list:
    #     #print(mail)
    #     #print(repr(mail))  #[1:-1]
    #     sender = mail.rstrip('\n')
    #     #print(repr(sender))  #[1:-1]
    #     #print(sender)

    # message info
    msg = MIMEMultipart()
    part = MIMEBase('application', "octet-stream")
    part.set_payload(open("scan.pdf", "rb").read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment; filename="scan.pdf"')
    msg.attach(part)

    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = COMMASPACE.join(receiver)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = "print"
    msg['Message-ID'] = ""
    part = MIMEBase('application', "pdf")
    with open("scan.pdf", 'rb') as file:
        part.set_payload(file.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition',
                        'attachment; filename="{}"'.format(op.basename("scan.pdf")))
        part.add_header('X-Attachment-Id', "") #add Id
        part.add_header('Content-ID', "") #add Id

    msg.attach(part)

    with smtplib.SMTP("", 25) as server:  # add smtp connection
        server.starttls()
        server.ehlo()
        server.login("apikey","")  # add API KEY
        server.sendmail(sender, receiver, msg.as_string())
        server.quit()
        print("mail sent from: " + mail)

print("finished.... ^-^")