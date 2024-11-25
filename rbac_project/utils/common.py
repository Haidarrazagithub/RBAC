from django.core.mail import send_mail
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination


class CustomPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'limit'

    def get_paginated_response(self, data):
        nexturl = self.get_next_link()
        if nexturl is not None:
            nexturl = f"/{nexturl.split('/', 3)[-1]}"
        prevurl = self.get_previous_link()
        if prevurl is not None:
            prevurl = f"/{prevurl.split('/', 3)[-1]}"
        return Response({
            'count': self.page.paginator.count,
            'next': nexturl,
            'previous': prevurl,
            'results': data
        })

#in local please not use it
def sendEmail(subject, message, recipient):
    """
    Sends email to provided recipient.
    param subject: Email subject
    param message: Message body that needs to be included in the email
    param recipient: recipient for the email deliver
    """
    try:
        send_mail(subject, message, "no-reply@haidar.com", [recipient], fail_silently=False)
        return True
    except Exception as e:
        print(f"Error while sending email to {recipient}: {str(e)}")
        return False