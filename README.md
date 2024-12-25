[example]: https://github.com/Kelll31/headersfire_ru/blob/main/img/example.png?raw=true "Example"

headerfire_ru
=========

Получаем заголовки версий из списка веб-сайтов. Бредовые заголовки игнорируются, поэтому отображаются только интересные заголовки по типу версий (и/или необычные заголовки).

Также отображаются хосты с отсутствующими заголовками безопасности или с небезопасными заголовками.

В выходных данных объединяются сайты с одинаковыми заголовками.

Целевым файлом может быть Nmap или службы могут выводить данные в формате XML (используйте -sV, чтобы обнаруживать http-серверы с нестандартными портами).

В противном случае предполагается, что целевым файлом является обычный текст с одним хостом в строке (протокол необязателен, предполагается http, если он не указан).

Usage
=====
![example]
$ headerfire.py \<файл или адрес\>
