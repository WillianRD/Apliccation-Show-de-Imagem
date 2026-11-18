# UnionBoard · Dashboard de Anúncios Mercado Livre

Protótipo web inicial (MVP) com HTML, CSS e JavaScript. Não precisa de instalação de Node.js para abrir a interface.

## Como executar
1. Extraia o ZIP.
2. Abra `index.html` em um navegador moderno.
3. Clique em **Importar CSV** para carregar uma exportação da planilha.
4. O CSV precisa ter cabeçalhos equivalentes a: `ID_MERCADOLIVRE`, `Nome do Anúncio`, `Status do Anúncio`, `Preço`, `Qualidade`, `Método de Envio`, `Vídeo`, `Quantidade de Visita`, `Vendas`.
5. Os nomes podem variar um pouco; a aplicação tenta reconhecer cabeçalhos comuns. Para maior compatibilidade, salve como CSV UTF-8.

## O que funciona
- KPIs de vendas, visitas, conversão estimada e qualidade média.
- Filtros por texto, status e faixa de qualidade.
- Ordenação por vendas, visitas, conversão, qualidade e preço.
- Gráficos de desempenho e distribuição de qualidade.
- Importação de CSV no navegador; os dados não são enviados a um servidor.
- Botão para restaurar os dados de demonstração.

## Limitações desta primeira versão
- Os dados de demonstração são fictícios.
- Importação apenas CSV; não lê XLSX diretamente.
- Não há backend, banco de dados, autenticação ou histórico persistente.
- Os dados importados ficam somente na memória da página e se perdem ao recarregar.
- A conversão é uma aproximação simples `vendas / visitas`; valide o significado de cada métrica antes de usar comercialmente.
- Não calcula margem ou lucro sem uma tabela confiável de custos.
- O gráfico usa Chart.js via CDN e requer conexão à internet para carregar a biblioteca.

## Próximas etapas recomendadas
1. Validar o CSV real da UnionBoard e ajustar o mapeamento de colunas.
2. Criar backend e banco de dados para histórico de snapshots e custos.
3. Adicionar autenticação, permissões, backups e logs.
4. Implementar XLSX, comparação entre períodos e plano de ação.
