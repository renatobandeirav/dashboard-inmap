function criarRotasInviabilidade({
  db,
  exigirLogin,
  exigirPermissao,
  responderErroInterno
}) {
  if (!db) {
    throw new Error(
      "A conexão com o banco é obrigatória nas rotas de inviabilidade."
    );
  }

  if (typeof exigirLogin !== "function") {
    throw new Error(
      "O middleware exigirLogin é obrigatório."
    );
  }

  if (typeof exigirPermissao !== "function") {
    throw new Error(
      "O middleware exigirPermissao é obrigatório."
    );
  }

  function registrar(app) {
    app.get(
      "/api/inviabilidade/mapa",
      exigirLogin,
      exigirPermissao("ver_crm_piperun"),
      async (req, res) => {
        try {
          const {
            mes,
            origem,
            categoria,
            cidade,
            bairro,
            vendedor,
            campanha,
            status = "ATIVA"
          } = req.query || {};

          const filtros = [];
          const parametros = [];

          if (mes) {
            if (!/^\d{4}-\d{2}$/.test(String(mes))) {
              return res.status(400).json({
                erro: true,
                mensagem:
                  "O mês deve estar no formato YYYY-MM."
              });
            }

            filtros.push(`
              DATE_FORMAT(
                COALESCE(
                  data_inviabilidade,
                  data_origem,
                  criado_em
                ),
                '%Y-%m'
              ) = ?
            `);

            parametros.push(String(mes));
          }

          if (origem) {
            const origemNormalizada =
              String(origem).toUpperCase();

            const origensPermitidas = [
              "PIPERUN",
              "IXC",
              "MANUAL"
            ];

            if (
              !origensPermitidas.includes(
                origemNormalizada
              )
            ) {
              return res.status(400).json({
                erro: true,
                mensagem: "Origem inválida."
              });
            }

            filtros.push("origem = ?");
            parametros.push(origemNormalizada);
          }

          if (categoria) {
            const categoriaNormalizada =
              String(categoria).toUpperCase();

            const categoriasPermitidas = [
              "CTO_LOTADA",
              "SEM_CTO",
              "METRAGEM",
              "ESTRUTURA",
              "FIBRASIL",
              "OUTRA"
            ];

            if (
              !categoriasPermitidas.includes(
                categoriaNormalizada
              )
            ) {
              return res.status(400).json({
                erro: true,
                mensagem: "Categoria inválida."
              });
            }

            filtros.push("categoria = ?");
            parametros.push(categoriaNormalizada);
          }

          if (cidade) {
            filtros.push("cidade = ?");
            parametros.push(String(cidade));
          }

          if (bairro) {
            filtros.push("bairro = ?");
            parametros.push(String(bairro));
          }

          if (vendedor) {
            filtros.push("vendedor_nome = ?");
            parametros.push(String(vendedor));
          }

          if (campanha) {
            filtros.push("campanha_nome = ?");
            parametros.push(String(campanha));
          }

          if (status) {
            const statusNormalizado =
              String(status).toUpperCase();

            const statusPermitidos = [
              "ATIVA",
              "RESOLVIDA",
              "DESCARTADA",
              "DUPLICADA"
            ];

            if (
              !statusPermitidos.includes(
                statusNormalizado
              )
            ) {
              return res.status(400).json({
                erro: true,
                mensagem: "Status inválido."
              });
            }

            filtros.push("status = ?");
            parametros.push(statusNormalizado);
          }

          const whereSql = filtros.length
            ? `WHERE ${filtros.join(" AND ")}`
            : "";

          const [pontos] = await db.query(
            `
            SELECT
              id,
              origem,
              origem_id,

              deal_id,
              lead_ixc_id,
              person_id,

              cliente,
              documento,

              motivo_codigo,
              motivo_nome,
              categoria,

              vendedor_nome,
              vendedor_ixc_id,

              campanha_nome,
              canal_venda_nome,
              plano_nome,

              cidade,
              bairro,
              endereco,
              numero,
              complemento,
              referencia,

              latitude,
              longitude,

              data_origem,
              data_inviabilidade,

              status,
              observacao,

              sincronizado_em,
              criado_em,
              atualizado_em
            FROM inviabilidades_mapa
            ${whereSql}
            ORDER BY
              COALESCE(
                data_inviabilidade,
                data_origem,
                criado_em
              ) DESC,
              id DESC
            `,
            parametros
          );

          const total = pontos.length;

          function agruparPor(campo) {
            const contagem = new Map();

            for (const ponto of pontos) {
              const valor =
                ponto[campo] ||
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

          const porCategoria =
            agruparPor("categoria");

          const porMotivo =
            agruparPor("motivo_nome");

          const porCidade =
            agruparPor("cidade");

          const porBairro =
            agruparPor("bairro");

          const porVendedor =
            agruparPor("vendedor_nome");

          const porCampanha =
            agruparPor("campanha_nome");

          const porOrigem =
            agruparPor("origem");

          const categorias = {
            cto_lotada:
              porCategoria.find(
                item => item.nome === "CTO_LOTADA"
              )?.quantidade || 0,

            sem_cto:
              porCategoria.find(
                item => item.nome === "SEM_CTO"
              )?.quantidade || 0,

            metragem:
              porCategoria.find(
                item => item.nome === "METRAGEM"
              )?.quantidade || 0,

            estrutura:
              porCategoria.find(
                item => item.nome === "ESTRUTURA"
              )?.quantidade || 0,

            fibrasil:
              porCategoria.find(
                item => item.nome === "FIBRASIL"
              )?.quantidade || 0,

            outra:
              porCategoria.find(
                item => item.nome === "OUTRA"
              )?.quantidade || 0
          };

          const [sincronizacaoRows] =
            await db.query(
              `
              SELECT
                MAX(sincronizado_em)
                  AS ultima_sincronizacao
              FROM inviabilidades_mapa
              `
            );

          return res.json({
            sucesso: true,

            filtros: {
              mes: mes || null,
              origem: origem || null,
              categoria: categoria || null,
              cidade: cidade || null,
              bairro: bairro || null,
              vendedor: vendedor || null,
              campanha: campanha || null,
              status: status || null
            },

            resumo: {
              total,
              categorias,

              principal_categoria:
                porCategoria[0] || null,

              principal_motivo:
                porMotivo[0] || null,

              principal_cidade:
                porCidade.find(
                  item =>
                    item.nome !==
                    "Não identificado"
                ) || null,

              principal_bairro:
                porBairro.find(
                  item =>
                    item.nome !==
                    "Não identificado"
                ) || null
            },

            agrupamentos: {
              categorias: porCategoria,
              motivos: porMotivo,
              cidades: porCidade,
              bairros: porBairro,
              vendedores: porVendedor,
              campanhas: porCampanha,
              origens: porOrigem
            },

            ultima_sincronizacao:
              sincronizacaoRows[0]
                ?.ultima_sincronizacao ||
              null,

            total_registros: total,
            pontos
          });

        } catch (erro) {
          return responderErroInterno(
            req,
            res,
            erro,
            "Erro ao consultar o mapa de inviabilidade"
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
  criarRotasInviabilidade
};