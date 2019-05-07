# Python Script - Socket Count

Dependência: [psutils]
 - pip install psutils
 
Integrado com o projeto py-zabbix para a função sender (obrigado ao projeto pelo código).

Exemplo:
Iniciar o "Server"
  - ncat --broker --listen -p 12345

Conectar alguns clientes:
  - ncat -v 127.0.0.1 12345
  
  
Funções:

* sender:
  - Responsável por enviar itens ao Zabbix via "Zabbix Sender"
* create:
  - Responsável por criar o JSON para o LLD do Zabbix
* discovery:
  - Responsável por ler o JSON para popular o Zabbix
* total [PORTA]:
  - Busca o TOTAL de uma porta especifica, utilizado para coleta automática dos itens
  
 

