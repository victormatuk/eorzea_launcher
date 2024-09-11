# Eorzea Launcher (Final Fantasy XIV)


Launcher simples de Final Fantasy 14 que não precisa ficar digitando login e nem OTP

*Se você não tem OTP ativado em sua conta, como profissional de cyber segurança, recomendo fortemente que o faça :)*

> [!WARNING]
> Este programa funciona somente no Windows e se o jogo foi adquirido pela Steam e se você possui um OTP configurado em sua conta, em breve teremos suporte ao launcher tradicional. Veja todas as próximas features no final do arquivo.

## Como utilizar (Usuários comuns)
1. Obtenha o segredo do seu OTP
2. Faça o download da última versão do executável em [Releases](https://github.com/victormatuk/eorzea_launcher/releases/download/prod/eorzea_launcher.exe) e siga os passos na tela.

## FAQ
1. O que é um OTP?
   - OTP significa "One-Time Password" (Senha de Uso Único). É uma senha temporária gerada para uma única sessão de autenticação ou transação. Os OTPs são usados como um fator de autenticação adicional para aumentar a segurança, especialmente em processos de login e transações financeiras. Eles são geralmente gerados por um dispositivo ou aplicativo específico e têm uma validade curta, o que ajuda a proteger contra ataques de interceptação e reutilização de senhas.
2. Como pegar o segredo do meu OTP para inserir no Script?
   1. Configurado no Google Authenticator do Chrome
      1.  Clique no ícone do Google Authenticator
      2.  Clique na engrenagem
         - ![Step](/images/step1.png)
      3. Clique em Backup
         - ![Step](/images/step2.png)
      3. Clique em Baixar o Arquivo de Backup
         - ![Step](/images/step3.png)
      4. Abra o arquivo baixado
         - ![Step](/images/step4.png)
      5. Copie o secret (este não é meu secret real)
         - ![Step](/images/step5.png)
      6. Delete permanentemente o arquivo baixado
         - ![Step](/images/step6.png)
   2. Diretamente da Mog Station
      1. Se você tiver OTP configurado em sua conta, primeiro será necessário removê-lo para reativá-lo.
      2. Vá para a Mog Station, faça login e clique em "One Time Password"
         - ![Step](/images/mogstation/step1.png)
      3. Clique em Software Authenticator
         - ![Step](/images/mogstation/step2.png)
      3. Clique em Registro do Software Authenticator
         - ![Step](/images/mogstation/step3.png)
      4. O site exibirá um código QR. Você precisa escaneá-lo com seu aplicativo OTP, como Google Authenticator, Authy, etc., e também com um leitor de QR Code para obter o segredo OTP. Ao fazer isso, você verá algo semelhante à imagem abaixo. Copie a parte destacada e use para configurar esta ferramenta.
         - ![Step](/images/mogstation/step4.png)
         - ![Step](/images/step5.png)
      5. Agora complete a configuração do seu OTP usando seu aplicativo OTP e inserindo o número na caixa de texto.
         - ![Step](/images/mogstation/step5.png)
      6. Clique em Concluir para Finalizar
         - ![Step](/images/mogstation/step6.png)
   3. Configurado em outros autenticadores
      - Todo OTP possui um secret, você deve arrumar uma maneira de obter este secret seja fazendo backup do seu OTP como mostrado acima ou lendo o QRCode com a câmera do celular e um leitor de QRCode. Se você fizer de outra maneira e quiser colaborar, entre em contato (matuk@antisec.com.br) para eu adicionar o seu método aqui :)
3. Não tenho OTP ativado na minha conta. Como ativar meu OTP?
   - Link para ativar seu OTP: [Square Enix Authenticator](https://www.square-enix-games.com/en_US/seaccount/otp/authenticator.html)
4. Errei ao digitar minha senha e/ou o segredo do meu OTP, o que faço?
   - Delete o arquivo de configuração eorzea_launcher.config e execute este programa novamente
5. Troquei minha senha e/ou meu OTP, o que faço?
   - Delete o arquivo de configuração eorzea_launcher.config e execute este programa novamente
6. Meu computador está executando tudo errado, parece clicar e digitar aleatoriamente
   - O Launcher funciona através de um timer e a tela pode não ter sido carregada no seu computador ainda, então você precisa configurar os tempos que quer para cada carregamento de tela. Para isso, após passar a etapa de configuração do programa, abra o arquivo eorzea_launcher.config e preencha em segundos as variáveis que começam com `waiting_time_to_...`, salve o arquivo de configuração e execute este programa novamente. Acompanhe os segundos no executável para verificar inconsistências.

## ROADMAP
- [x] Steam Launcher support
- [x] Guide the user through setup using a "Wizard" model
- [x] Multilingual support
- [ ] Read QRCode from image to configure OTP
- [ ] Password-only authentication (For players who have not set up OTP)
- [ ] Support for Traditional Launcher
- [ ] Add a function to change the password saved in configuration file
- [ ] Add a GUI
- [ ] Capture information about the processor, memory, and graphics card to generate the values for variables starting with `waiting_time_to_...`

## Como utilizar (Desenvolvedores)
1. Clone este repositório
2. Faça o download dos requirements.txt
   - `pip install -r requirements.txt`
3. Instale o pyinstaller
   - `pip install pyinstaller`
4. Compile um executável a partir do arquivo eorzea_launcher.py ou utilize python eorzea_launcher.py diretamente.
   - `pyinstaller --onefile eorzea_launcher.py`