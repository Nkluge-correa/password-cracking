import math
import dash
import random
import pandas as pd
import dash_daq as daq
from hashlib import sha1
import dash_bootstrap_components as dbc
from dash import dcc, html, Output, Input, State, dash_table

app = dash.Dash(__name__,
                meta_tags=[
                    {'name': 'viewport', 'content': 'width=device-width, initial-scale=1.0, maximum-scale=1.2, minimum-scale=0.5,'}],
                external_stylesheets=[dbc.themes.SLATE])

server = app.server
app.title = 'Password Security 🔒'


with open('dictionary.txt', encoding='utf8') as fp:
    dictionary = [line.strip() for line in fp]
    fp.close()

leak = pd.read_csv('users_passwords_dump.csv')


def dictionary_attack(dictionary_word, target_hash):
    pass_bytes = dictionary_word.encode('utf-8')
    pass_hash = sha1(pass_bytes)
    digest = pass_hash.hexdigest()
    if digest == target_hash:
        return True


with open('words_466k.txt', encoding='utf8') as fp:
    word_password_bag = [line.strip() for line in fp]
    fp.close()


def has_numbers(inputstring):
    return any(char.isdigit() for char in inputstring)


def has_lower(inputstring):
    return any(char.islower() for char in inputstring)


def has_upper(inputstring):
    return any(char.isupper() for char in inputstring)


def has_symbol(inputstring):
    return any(not c.isalnum() for c in inputstring)


leak_table = html.Div(children=[

    dash_table.DataTable(
        data=leak.to_dict(orient='records'),
        columns=[{'id': x, 'name': x, 'presentation': 'markdown'} if x ==
                 'users' else {'id': x, 'name': x} for x in leak.columns],
        style_table={'text-align': 'justify', 'text-justify': 'inter-word',
                     'height': '400px', 'overflowY': 'scroll'},
        page_current=0,
        page_size=50,
        style_cell={
            'text-align': 'justify', 'text-justify': 'inter-word', 'fontSize': 16, 'padding': '10px',
        },
        style_data={
            'whiteSpace': 'normal',
            'height': 'auto'
        },
        style_header={
            'fontWeight': 'bold',
            'text-align': 'left',
            'fontSize': 16
        },
    ),

], style={'margin-left': '15px', 'margin-right': '20px', 'margin-top': '10px'})

modal_hash = html.Div(
    [
        dbc.Button('Hash?', id='info-button', n_clicks=0,
                   outline=True, color='warning'),
        dbc.Modal(
            [
                dbc.ModalHeader(dbc.ModalTitle(dcc.Markdown(
                    '# What is a Hash Function?'))),
                dbc.ModalBody([dcc.Markdown('''
                                A [hash function](https://en.wikipedia.org/wiki/Hash_function) is a function that **takes a set of inputs of any arbitrary size and fits them into a table or other data structure that contains fixed-size elements**.
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                A cryptographic hash function (**CHF**) is a mathematical [algorithm](https://en.wikipedia.org/wiki/Algorithm "Algorithm") that [maps](https://en.wikipedia.org/wiki/Map_(mathematics) "Map (mathematics)") data of an arbitrary size (often called the "_message_") to a [bit array](https://en.wikipedia.org/wiki/Bit_array "Bit array") of a fixed size (the "_[hash value](https://en.wikipedia.org/wiki/Hash_value "Hash value")_", or "_digest_"). It is a [one-way function](https://en.wikipedia.org/wiki/One-way_function "One-way function"), that is, a function for which it is practically infeasible to invert or reverse the computation. This also means that there can be **data-loss** during the hashing process.
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                               ## SHA-1

                               ---

                               '''),
                               dcc.Markdown('''

                                ```python

                                password101 = SHA-1 = 523cf99e800d57d0ff0ac7b97e04ebc2b9b4b263

                                ```
                                ''', style={'font-size': 24, 'text-align': 'center'}), html.Br(),
                               dcc.Markdown('''
                                **SHA-1** (_Secure Hash Algorithm 1_) is a cryptographically **broken** but still widely used [hash function](https://en.wikipedia.org/wiki/Hash_function "Hash function") which takes an input and produces a 160-bit (20-byte) hash value known as a [message digest](https://en.wikipedia.org/wiki/Message_digest "Message digest") - typically rendered as a [hexadecimal](https://en.wikipedia.org/wiki/Hexadecimal "Hexadecimal") number, 40 digits long. It was designed by the United States [National Security Agency](https://en.wikipedia.org/wiki/National_Security_Agency "National Security Agency"), and is a U.S. [Federal Information Processing Standard](https://en.wikipedia.org/wiki/Federal_Information_Processing_Standard "Federal Information Processing Standard").
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                 In this example of attack, we are trying to break a SHA-1 hash, as a mere example on password safety (_Do not do this against passwords you do not own!_).
                                 ''', style={'font-size': 24, 'text-align': 'justify',
                                             'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                               
                               ## Leaks ☣️
                               
                               ---

                               '''),
                               dcc.Markdown('''
                                User-password often *leak* onto the Internet. **Leaked data frequently includes hashed passwords**, like the infamous [RockYou data breach](https://en.wikipedia.org/wiki/RockYou#:~:text=In%20December%202009%2C%20RockYou%20experienced,%2Dyear%2Dold%20SQL%20vulnerability.). **RockYou** was a company that developed widgets for [MySpace](https://en.wikipedia.org/wiki/MySpace "MySpace") and implemented applications for various social networks (e.g., Facebook). In December 2009, RockYou experienced a data breach resulting in the exposure of over 32 million user accounts. This resulted from storing user data in an unencrypted database (including user passwords in plain text instead of using a [cryptographic hash](https://en.wikipedia.org/wiki/Cryptographic_hash "Cryptographic hash")) and not patching a ten-year-old [SQL](https://en.wikipedia.org/wiki/SQL "SQL") vulnerability.
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                This leak, and many others, help attackers create "_dictionary's_" that can be use to help password-cracking. For example, the [RockYou2021](https://github.com/ohmybahgosh/RockYou2021.txt) has **100 GB** of plain leaked passwords ready to be used in [dictionary attacks](https://en.wikipedia.org/wiki/Dictionary_attack).
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                Below you find a **fake**, and **totally fabricated**, leak with (**fake**) user names from a (**non-existent**) website/server that at least had the *conscience to encrypt its users' passwords*. But they did it with a very weak hash (by contemporary encryption and cyber security standards): **[SHA-1](https://crypto.stackexchange.com/questions/3690/why-is-sha-1-considered-broken)**. *Shall we try to break any of them?*
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               leak_table,
                               ]),
                dbc.ModalFooter(
                    html.Div([dbc.Button('Close', id='close-body-scroll-2', className='ms-auto',
                             n_clicks=0, color='warning', outline=False)], style={'display': 'inline-block'})
                ),
            ],
            id='modal-body-scroll-2',
            scrollable=True,
            fullscreen=True,
            is_open=False,
        ),
    ], style={
        'margin-left': '15px',
        'margin-right': '50px',
        'margin-bottom': '15px'
    },

)

modal_trust = html.Div(
    [
        dbc.Button('Password Cracking?', id='trust-button',
                   n_clicks=0, outline=True, color='warning'),
        dbc.Modal(
            [
                dbc.ModalHeader(dbc.ModalTitle(dcc.Markdown(
                    '# How do you do this?'), style={})),
                dbc.ModalBody([dcc.Markdown('''
                                In [cryptanalysis](https://en.wikipedia.org/wiki/Cryptanalysis) and [computer security](https://en.wikipedia.org/wiki/Computer_security "Computer security"), **password cracking** is the process of recovering passwords from data that has been stored in or transmitted by a computer syste  in scrambled form. A common approach ([brute-force attack](https://en.wikipedia.org/wiki/Brute-force_attack "Brute-force attack")) is to repeatedly try guesses for the password and to check them against an available [cryptographic hash](https://en.wikipedia.org/wiki/Cryptographic_hash_function "Cryptographic hash function") of the password.
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                What we are doing here is a [dictionary attack](https://en.wikipedia.org/wiki/Dictionary_attack). *A dictionary attack is based on trying all the strings in a pre-arranged listing.* I (the programmer behind this page) am using a dictionary of my own making, containing around **3.7 million** words and possible passwords (**not even close to the monster that [RockYou2021](https://github.com/ohmybahgosh/RockYou2021.txt) is**).
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('The program is basically:', style={
                                            'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                ````python

                                for  word  in  dictionary:
                                    if  hash ==  sha1(word):
                                        return word
                                    else:
                                        continue

                                ```` 
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                The code for this implementation can be accessed on [GitHub](https://github.com/Nkluge-correa), but there are many other tools ready for this kind of attack (many come pre-installed on [Kali-Linux](https://www.kali.org/)). However, remember that: *using a password cracking method to access one's own password is legal*. **Using these methods or tools to gain access to someone else's password can lead to criminal charges.**
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                 "_I do not believe you are cracking these passwords! You are storing these words whiteout hashing! The cake is a lie!_"
                                 ''', style={'font-size': 24, 'text-align': 'center'}), html.Br(),
                               dcc.Markdown('''
                                Use any other online [SHA-1](http://www.sha1-online.com/) generator and bring a candidate password-hash here. If your password is **strong**, *and not in my dictionary*, you win!
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               ]),
                dbc.ModalFooter(
                    html.Div([dbc.Button('Close', id='close-body-scroll-3', className='ms-auto',
                             n_clicks=0, color='warning', outline=False)], style={'display': 'inline-block'})
                ),
            ],
            id='modal-body-scroll-3',
            scrollable=True,
            fullscreen=True,
            is_open=False,
        ),
    ], style={
        'margin-left': '15px',
        'margin-right': '50px',
        'margin-bottom': '15px'
    },

)

modal_entropy = html.Div(
    [
        html.Div([dbc.Button('Password Security', id='entropy-button', n_clicks=0, outline=True,
                 color='warning')], style={'display': 'inline-block', 'text-align': 'left'}),
        dbc.Modal(
            [
                dbc.ModalHeader(dbc.ModalTitle(dcc.Markdown(
                    '# How to create good passwords?'), style={})),
                dbc.ModalBody([dcc.Markdown('''
                                Here are a couple of basic instructions on how to create a "_not-super-easy-to-break_" password:
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                1.  **Never use personal information**: You shouldn't reference personal information. You would not believe how many examples of words + dates/numbers are available. Also, you could get [phished](https://en.wikipedia.org/wiki/Phishing).
                                2.  **Create passwords that have big entropy levels**: *I'll explain password entropy bellow*.
                                3.  **Passwords should be long**: Safe passwords are at least 16 characters long.
                                4.  **Never repeat passwords:** Reusing the same password for different accounts puts you at risk of  [credential stuffing](https://en.wikipedia.org/wiki/Credential_stuffing)  attacks. Create one master password (a **really good one**) and use it to lock your other passwors in a [password manager](https://en.wikipedia.org/wiki/Password_manager).
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                               
                               ## Password Entropy
                               
                               ---

                               '''),
                               dcc.Markdown('''
                                In 2019, the United Kingdom’s [NCSC](https://en.wikipedia.org/wiki/National_Cyber_Security_Centre_(United_Kingdom)) analyzed public databases of breached accounts **to see which words, phrases, and strings people used**. Top of the list was `123456`, appearing in more than **23 million passwords**. The second-most popular string, `123456789`, while the top five included `qwerty`, `password` and `1111111`. As you can see, people do not give much credit to how easy it is to crack trivial passwords like these. To avoid getting your password used as another sample in a dictionary attack, you need to make your password stronger.
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                **Password strength**  is a measure of the effectiveness of a  [password] against guessing or  [brute-force attacks](https://en.wikipedia.org/wiki/Brute-force_attack "Brute-force attack"). In its usual form, it estimates how many trials an attacker who does not have direct access to the password would need, on average, to guess it correctly. 
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                It is usual in the computer industry to specify password strength in terms of [information entropy](https://en.wikipedia.org/wiki/Information_entropy "Information entropy"), which is measured in [bits](https://en.wikipedia.org/wiki/Bit "Bit"), being a concept related to [Shannon's entropy measure](https://en.wikipedia.org/wiki/Entropy_(information_theory)). 
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                Instead of the number of guesses needed to find the password with certainty, the [base-2 logarithm](https://en.wikipedia.org/wiki/Binary_logarithm "Binary logarithm") of that number is given, which is commonly referred to as the number of "_entropy bits_" in a password. A password with an entropy of 42 bits calculated in this way would be as strong as a string of 42 bits chosen randomly. Put another way, a password with an entropy of 42 bits would require 242 (4,398,046,511,104) attempts to exhaust all possibilities during a [brute force search](https://en.wikipedia.org/wiki/Brute_force_search "Brute force search"). Thus, increasing the entropy of the password by one bit doubles the number of guesses required, making an attacker's task twice as difficult. On average, ***an attacker will have to try half the possible number of passwords before finding the correct one.***
                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('You can calculate your password entropy by this equation:', style={
                                            'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                ```markdown

                                E = L x log2(R)
                                
                                ```
                                ''', style={'font-size': 24, 'text-align': 'center'}), html.Br(),
                               dcc.Markdown('where:', style={
                                            'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dcc.Markdown('''
                                - E = password entropy;
                                - L = Password length, i.e., the number of characters in the password;
                                - R = Size of the pool of unique characters from which we build the password.\n

                                Also:

                                - < 28 bits = Very Weak;  
                                - 28 - 35 bits = Weak;
                                - 36 - 59 bits = Reasonable; 
                                - 60 - 127 bits = Strong;
                                - 128 + bits = Very Strong.

                                ''', style={'font-size': 24, 'text-align': 'justify',
                                            'text-justify': 'inter-word'}), html.Br(),
                               dbc.Label(dcc.Markdown(
                                   'Check your password strength on the cell bellow!', style={'font-size': 24, 'text-align': 'justify',
                                                                                              'text-justify': 'inter-word'})),
                               dbc.Input(placeholder="Dummy-Password goes here...",
                              type="password", id='dummy-password'),
                               html.Div([dbc.Card(dbc.CardBody([dcc.Markdown(
                                   " ", style={'font-size': 24}, id='password-entropy')]))]), html.Br(),
                               dcc.Markdown('If you do not belive this page, belive [XKCD](https://xkcd.com/936/)', style={
                                   'font-size': 24, 'text-align': 'center'}), html.Br(),
                               html.Div([html.Img(id='img_1', src=app.get_asset_url('password_strength.png'), height=601, width=740, style={
                                   'height': '50%', 'width': '50%'})], style={'textAlign': 'center'})

                               ]),
                dbc.ModalFooter(
                    html.Div([dbc.Button('Close', id='close-body-scroll-4', className='ms-auto',
                             n_clicks=0, color='warning', outline=False)], style={'display': 'inline-block'})
                ),
            ],
            id='modal-body-scroll-4',
            scrollable=True,
            fullscreen=True,
            is_open=False,
        ),
        html.Div([dbc.Button('Generate Password', id='generate-password-button', n_clicks=0, outline=True,
                 color='warning', style={'margin-left': '15px'})], style={'display': 'inline-block', 'text-align': 'right'}),
        html.Div([daq.NumericInput(min=2, max=10, value=4, id='generate-password-number',
                 style={'margin-left': '15px'})], style={'display': 'inline-block', 'text-align': 'right'}),
        html.Div([dbc.FormText(dcc.Markdown("_Choose the number of words in your password (>= 4 is recommended)_",
                 style={'margin-left': '15px', }))], style={'display': 'inline-block', 'text-align': 'right'})
    ], style={
        'margin-left': '15px',
        'margin-right': '150px',
        'margin-bottom': '15px',
    },

)

card_0 = html.Div(
    [
        dbc.Card(
            dbc.CardBody([
                dcc.Markdown(" ", id='hash')
            ])
        ),
    ], style={'margin-left': '15px', 'margin-bottom': '15px'}
)

card_1 = dcc.Loading(id='loading', type='circle', children=[html.Div([
    dbc.Card(
        dbc.CardBody([
            dcc.Markdown(" ", id='password-cracked')
        ])
    ),
], style={'margin-left': '15px', 'margin-bottom': '15px'})])

card_2 = html.Div(
    [
        dbc.Card(
            dbc.CardBody([
                dcc.Markdown(" ", id='generated-password')
            ])
        ),
    ], style={'margin-left': '15px', 'margin-bottom': '15px'}
)

password_input = html.Div(
    [
        dbc.Label(dcc.Markdown("## Let's first hash your password",
                  style={'margin-left': '15px', })),
        modal_hash,
        dbc.Input(placeholder="Password goes here...", type="password",
                  id='password', style={'margin-left': '15px', }),
        dbc.FormText(dcc.Markdown("What about _password101_",
                     style={'margin-top': '5px', 'margin-left': '15px', })),
    ]
)

hash_input = html.Div(
    [
        dbc.Label(dcc.Markdown("## Submit your hash here",
                  style={'margin-left': '15px'})),
        modal_trust,
        dbc.Input(placeholder="Hash goes here...", type="text",
                  id='hash-password', style={'margin-left': '15px', }),
        html.Div([dbc.Button('Submit', id='submit-button', n_clicks=0, outline=True, color='warning',
                 style={'margin-top': '15px', 'margin-left': '15px', })], style={'text-align': 'right'}),
        dbc.FormText(dcc.Markdown(
            "What about _523cf99e800d57d0ff0ac7b97e04ebc2b9b4b263_", style={'margin-left': '15px'})),
    ]
)

generator_input = html.Div(
    [
        dbc.Label(dcc.Markdown("## UPGRADE YOUR PASSWORD! 👨🏽‍💻🔒",
                  style={'margin-left': '15px'})), html.Br(),
        modal_entropy, card_2
    ]
)


app.layout = dbc.Container(
    fluid=False,
    children=[
        html.H1('Dictionary Attack & Password Generator 👾🔒', style={'textAlign': 'center',
                                                                    'margin-top': '20px'}),
        html.Hr(),
        dbc.Row([
            dbc.Col([], md=1),
            dbc.Col([
                password_input,
                card_0,
                hash_input,
                card_1,
                generator_input,
            ], md=10),
            dbc.Col([], md=1),
        ]),
        html.Hr(),

    ],
)


@app.callback(
    Output('hash', 'children'),
    [Input('password', 'value')],
    prevent_initial_call=True)
def output_hash(value):
    text = value.replace(" ", "")
    if text == '':
        return ''
    else:
        pass_bytes = text.encode('utf-8')
        pass_hash = sha1(pass_bytes)
        digest = pass_hash.hexdigest()
        return digest


@app.callback(
    Output('password-cracked', 'children'),
    [Input('submit-button', 'n_clicks_timestamp')],
    [State('hash-password', 'value')])
def cracking(click, value):
    if click is not None:
        for word in dictionary:
            if dictionary_attack(word, value) == True:
                x = f'The password is: {word}.'
                return x
            if word == dictionary[-1]:
                return 'No password found in dictionary.'
            else:
                continue


@app.callback(
    Output('password-entropy', 'children'),
    [Input('dummy-password', 'value')],
    prevent_initial_call=True)
def password_entropy(value):
    if len(value) <= 1:
        return '''
        ````bash
        Password is to short...
        ````
        '''
    else:
        text = value.replace(" ", "")
        x = 0
        if has_numbers(text) is True:
            x += 10
        if has_lower(text) is True:
            x += 26
        if has_upper(text) is True:
            x += 26
        if has_symbol(text) is True:
            x += 32
        return f'''

                - This password has an entropy of: `{round(len(text) * math.log2(x), 2)} bits = {len(text)}` * log2(`{x}`).
                - To guess this password, character-by-character, via brute-force, it would take up to: 2 ** `{round(len(text) * math.log2(x), 2)}` = `{'{:,.2f}'.format(int(2 ** (round(len(text) * math.log2(x), 2))))}` guesses.
                - At 10,000 guesses per second without GPU, would take up to `{(int(2 ** (round(len(text) * math.log2(x))))/10000)}` seconds to crack this password.
                - Equivalent to `{'{:,.2f}'.format((int(2 ** (round(len(text) * math.log2(x), 2)))/10000)/86400)}` days.
                
                '''


@app.callback(
    Output('generated-password', 'children'),
    [Input('generate-password-button', 'n_clicks')],
    [State('generate-password-number', 'value')])
def generate_password(click, value):
    if click > 0:
        password = []
        for i in range(int(value)):
            item = random.choice(word_password_bag)
            password.append(item)
        password_txt = ' '.join(password)
        password_len = ''.join(password)
        x = 0
        if has_numbers(password_txt) is True:
            x += 10
        if has_lower(password_txt) is True:
            x += 26
        if has_upper(password_txt) is True:
            x += 26
        if has_symbol(password_txt) is True:
            x += 32
        return f'''
        - Your password is: `{password_txt}`
        - These words were choosen out of `{'{:,.2f}'.format(len(word_password_bag))}` possible words.'
        - Space of possible passwords = `{'{:,.2f}'.format(len(word_password_bag) ** int(value))}`.
        - Maximum number of operations to Brute Force your passaword: ~ `{'{:,.2f}'.format(int(2 ** (16 * int(value))))}`.
        - This password has an entropy of: `{round(len(password_len) * math.log2(x), 2)}` bits.
        - To guess this password, character-by-character, via brute-force, it would take up to: 2 ** `{round(len(password_len) * math.log2(x), 2)}` = `{'{:,.2f}'.format(int(2 ** (round(len(password_len) * math.log2(x), 2))))}` guesses.
        - At 10,000 guesses per second without GPU, would take up to `{(int(2 ** (round(len(password_len) * math.log2(x))))/10000)}` seconds to crack this password.
        - Equivalent to `{'{:,.2f}'.format((int(2 ** (round(len(password_len) * math.log2(x), 2)))/10000)/86400)}` days.
        '''


@app.callback(
    Output('modal-body-scroll-2', 'is_open'),
    [
        Input('info-button', 'n_clicks'),
        Input('close-body-scroll-2', 'n_clicks'),
    ],
    [State('modal-body-scroll-2', 'is_open')],
)
def toggle_modal(n1, n2, is_open):
    if n1 or n2:
        return not is_open
    return is_open


@app.callback(
    Output('modal-body-scroll-3', 'is_open'),
    [
        Input('trust-button', 'n_clicks'),
        Input('close-body-scroll-3', 'n_clicks'),
    ],
    [State('modal-body-scroll-3', 'is_open')],
)
def toggle_modal(n1, n2, is_open):
    if n1 or n2:
        return not is_open
    return is_open


@app.callback(
    Output('modal-body-scroll-4', 'is_open'),
    [
        Input('entropy-button', 'n_clicks'),
        Input('close-body-scroll-4', 'n_clicks'),
    ],
    [State('modal-body-scroll-4', 'is_open')],
)
def toggle_modal(n1, n2, is_open):
    if n1 or n2:
        return not is_open
    return is_open


if __name__ == '__main__':
    app.run_server(debug=False)
