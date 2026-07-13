function criarRotasPiperun({
  db,
  exigirLogin,
  exigirPermissao,
  responderErroInterno
}) {
  if (!db) {
    throw new Error("A conexão com o banco é obrigatória nas rotas Piperun.");
  }

  if (typeof exigirLogin !== "function") {
    throw new Error("O middleware exigirLogin é obrigatório.");
  }

  if (typeof exigirPermissao !== "function") {
    throw new Error("O middleware exigirPermissao é obrigatório.");
  }

  function registrar(app) {
    app.get(
      "/api/piperun/perdidos",
      exigirLogin,
      exigirPermissao("ver_crm_piperun"),
      async (req, res) => {
        try {
          const {
            mes,
            vendedor,
            cidade,
            bairro,
            etapa,
            campanha,
            canal
          } = req.query || {};

          const filtros = [];
          const parametros = [];

          if (mes) {
            if (!/^\d{4}-\d{2}$/.test(String(mes))) {
              return res.status(400).json({
                erro: true,
                mensagem: "O mês deve estar no formato YYYY-MM."
              });
            }

            filtros.push(
              "DATE_FORMAT(data_origem, '%Y-%m') = ?"
            );

            parametros.push(String(mes));
          }

          if (vendedor) {
            filtros.push("vendedor_nome = ?");
            parametros.push(String(vendedor));
          }

          if (cidade) {
            filtros.push("cidade = ?");
            parametros.push(String(cidade));
          }

          if (bairro) {
            filtros.push("bairro = ?");
            parametros.push(String(bairro));
          }

          if (etapa) {
            filtros.push("etapa = ?");
            parametros.push(String(etapa));
          }

          if (campanha) {
            filtros.push("campanha_nome = ?");
            parametros.push(String(campanha));
          }

          if (canal) {
            filtros.push("canal_venda_nome = ?");
            parametros.push(String(canal));
          }

          const whereSql = filtros.length
            ? `WHERE ${filtros.join(" AND ")}`
            : "";

          const [oportunidades] = await db.query(
            `
            SELECT
              deal_id,
              person_id,
              pipeline_id,
              stage_id,
              etapa,
              status_piperun,
              cliente,

              vendedor_nome,
              vendedor_ixc_id,

              responsavel_piperun_id,
              responsavel_piperun_nome,

              cidade,
              bairro,
              latitude,
              longitude,

              campanha_ixc_id,
              campanha_nome,

              canal_venda_ixc_id,
              canal_venda_nome,

              plano_ixc_id,
              plano_nome,

              valor,
              mrr,
              instalacao_valor,
              instalacao_gratis,

              data_origem,
              data_entrada_funil,
              data_entrada_etapa,

              lead_time,
              origin_id,

              criado_piperun_em,
              atualizado_piperun_em,
              sincronizado_em
            FROM piperun_oportunidades
            ${whereSql}
            ORDER BY
              data_origem DESC,
              deal_id DESC
            `,
            parametros
          );

          const total = oportunidades.length;

          const valorPotencialPerdido = oportunidades.reduce(
            (soma, oportunidade) => {
              return soma + Number(oportunidade.valor || 0);
            },
            0
          );

          const mrrPerdido = oportunidades.reduce(
            (soma, oportunidade) => {
              return soma + Number(oportunidade.mrr || 0);
            },
            0
          );

          const instalacaoPerdida = oportunidades.reduce(
            (soma, oportunidade) => {
              return soma + Number(
                oportunidade.instalacao_valor || 0
              );
            },
            0
          );

          const ticketMedio =
            total > 0
              ? valorPotencialPerdido / total
              : 0;

          function agruparPor(campo) {
            const contagem = new Map();

            for (const oportunidade of oportunidades) {
              const valor =
                oportunidade[campo] ||
                "Não identificado";

              contagem.set(
                valor,
                (contagem.get(valor) || 0) + 1
              );
            }

            return [...contagem.entries()]
              .map(([nome, quantidade]) => ({
                nome,
                quantidade,
                percentual:
                  total > 0
                    ? Number(
                        (
                          (quantidade / total) *
                          100
                        ).toFixed(2)
                      )
                    : 0
              }))
              .sort((a, b) => {
                return b.quantidade - a.quantidade;
              });
          }

          function arredondarMoeda(valor) {
            return Number(Number(valor || 0).toFixed(2));
            }

          const porEtapa = agruparPor("etapa");
          const porCidade = agruparPor("cidade");
          const porBairro = agruparPor("bairro");
          const porVendedor = agruparPor("vendedor_nome");
          const porCampanha = agruparPor("campanha_nome");
          const porCanal = agruparPor("canal_venda_nome");

          const [opcoes] = await db.query(
            `
            SELECT
              MAX(sincronizado_em) AS ultima_sincronizacao
            FROM piperun_oportunidades
            `
          );

          function obterPrincipalIdentificado(lista) {
            return (
                lista.find(item => {
                return (
                    item.nome &&
                    item.nome !== "Não identificado" &&
                    item.nome !== "-"
                );
                }) || null
            );
            }

          return res.json({
            sucesso: true,

            filtros: {
              mes: mes || null,
              vendedor: vendedor || null,
              cidade: cidade || null,
              bairro: bairro || null,
              etapa: etapa || null,
              campanha: campanha || null,
              canal: canal || null
            },

            resumo: {
              total,
                valor_potencial_perdido: arredondarMoeda(
                valorPotencialPerdido
                ),

                mrr_perdido: arredondarMoeda(
                mrrPerdido
                ),

                instalacao_perdida: arredondarMoeda(
                instalacaoPerdida
                ),

                ticket_medio: arredondarMoeda(
                ticketMedio
                ),

                principal_motivo:
                obterPrincipalIdentificado(porEtapa),

                principal_cidade:
                obterPrincipalIdentificado(porCidade),

                principal_bairro:
                obterPrincipalIdentificado(porBairro),

                vendedor_mais_afetado:
                obterPrincipalIdentificado(porVendedor)
            },

            agrupamentos: {
              etapas: porEtapa,
              cidades: porCidade,
              bairros: porBairro,
              vendedores: porVendedor,
              campanhas: porCampanha,
              canais: porCanal
            },

            ultima_sincronizacao:
              opcoes[0]?.ultima_sincronizacao ||
              null,

            total_registros: total,
            oportunidades
          });

        } catch (erro) {
          return responderErroInterno(
            req,
            res,
            erro,
            "Erro ao consultar perdas da Piperun"
          );
        }
      }
    );
  }

  return {
    registrar
  };
}

module.exports = {
  criarRotasPiperun
};