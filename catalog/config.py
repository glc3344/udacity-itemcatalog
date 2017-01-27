from authomatic.providers import oauth1, oauth2


CONFIG = {

    'tw': {  # Your internal provider name

        # Provider class
        'class_': oauth1.Twitter,

        # Twitter is an AuthorizationProvider so we need to set several other properties too:
        'consumer_key': 'cjSACrUJ6Y2rCZlyvjlWnHn4f',
        'consumer_secret': '7h75s3iAoyNfaSefnnONBJ3vsy7bEFsSbOxm9UEfNlP7xhyFbl',
    },

    'fb': {

        'class_': oauth2.Facebook,

        # Facebook is an AuthorizationProvider too.
        'consumer_key': '########################',
        'consumer_secret': '########################',

        # But it is also an OAuth 2.0 provider and it needs scope.
        'scope': ['user_about_me', 'email', 'publish_stream'],
    },

    'google': {
        'class_': oauth2.Google,
        'consumer_key': '458401153152-22gtge8j5ajft96euj2ubkk1vdtmr6sk.apps.googleusercontent.com',
        'consumer_secret': 'CgEnYAjJXcMcKd_SQiY5npRa',
        'scope': oauth2.Google.user_info_scope + [
            'https://www.googleapis.com/auth/calendar',
            'https://mail.google.com/mail/feed/atom',
            'https://www.googleapis.com/auth/drive',
            'https://gdata.youtube.com'],
        '_apis': {
            'List your calendars': ('GET',
                                    'https://www.googleapis.com/calendar/v3/users/me/calendarList'),
            'List your YouTube playlists': ('GET',
                                            'https://gdata.youtube.com/feeds/api/users/default/playlists?alt=json'),
        },
    },

}
