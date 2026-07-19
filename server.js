require("dotenv").config({ quiet: true });
const session = require("express-session");
const express = require("express");
const axios = require("axios");
const { vendedores, tecnicos, coresTecnicos } = require("./nome");
const { usuariosDashboard, equipesComerciais } = require("./usuarios");
const bcrypt = require("bcrypt");
const db = require("./db");
const path = require("path");
const multer = require("multer");
const rateLimit = require("express-rate-limit");


const app = express();
app.use(express.json({
  limit: "1mb"
}));



const limitadorLoginSistema = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: {
    erro: true,
    mensagem: "Muitas tentativas de login. Aguarde alguns minutos e tente novamente."
  }
});

const limitadorLoginPortal = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 3,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: {
    erro: true,
    mensagem: "Muitas tentativas de acesso. Aguarde alguns minutos e tente novamente."
  }
});

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET não configurado no arquivo .env.");
}

if (process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET precisa ter pelo menos 32 caracteres.");
}

app.disable("x-powered-by");

app.set("trust proxy", 1);

const ambienteAplicacao =
  process.env.NODE_ENV === "production"
    ? "prod"
    : "dev";

const nomeCookieSessao =
  ambienteAplicacao === "prod"
    ? "inmap.prod.sid"
    : "inmap.dev.sid";

app.use(session({
  name: nomeCookieSessao,
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

async function autenticarUsuario(usuario, senha) {
  const [rows] = await db.query(
    `
    SELECT *
    FROM usuarios_dashboard
    WHERE usuario = ?
      AND ativo = 1
    LIMIT 1
    `,
    [usuario]
  );

  if (!rows.length) return null;

  const user = rows[0];

  const senhaValida = await bcrypt.compare(senha, user.senha_hash);

  if (!senhaValida) return null;

  const [permissoesRows] = await db.query(
    `
    SELECT permissao
    FROM permissoes_usuario
    WHERE usuario_id = ?
    `,
    [user.id]
  );

  user.permissoes = permissoesRows.map((item) => item.permissao);

  return user;
}

function exigirLogin(req, res, next) {
  if (req.session && req.session.logado) {
    return next();
  }

  return res.status(401).json({
    erro: true,
    mensagem: "Acesso não autorizado."
  });
}

function exigirSuperAdmin(req, res, next) {
  const usuario = req.session?.usuario;

  if (!usuario || usuario.perfil !== "super_admin") {
    return res.status(403).json({
      erro: true,
      mensagem: "Acesso não autorizado."
    });
  }

  return next();
}

function registrarDebugGet(caminho, ...handlers) {
  if (process.env.NODE_ENV !== "production") {
    app.get(caminho, exigirLogin, exigirSuperAdmin, ...handlers);
  }
}

function registrarDebugPost(caminho, ...handlers) {
  if (process.env.NODE_ENV !== "production") {
    app.post(caminho, exigirLogin, exigirSuperAdmin, ...handlers);
  }
}


function exigirPermissao(permissao) {
  return function (req, res, next) {
    const usuario = req.session?.usuario;

    if (!usuario) {
      console.warn("[ACESSO NEGADO - PERMISSAO]", {
        usuario_id: null,
        usuario: null,
        nome: null,
        perfil: null,
        equipe: null,
        rota: req.originalUrl,
        metodo: req.method,
        ip: req.ip,
        user_agent: req.get("User-Agent") || null,
        referer: req.get("Referer") || null,
        permissao_exigida: permissao,
        permissoes_usuario: [],
        data_hora: new Date().toISOString()
      });

      return res.status(401).json({
        erro: true,
        mensagem: "Usuário não autenticado."
      });
    }

    if (usuario.perfil === "super_admin") {
      return next();
    }

    const permissoes = Array.isArray(usuario.permissoes)
      ? usuario.permissoes
      : [];

    if (permissoes.includes(permissao)) {
      return next();
    }

    console.warn("[ACESSO NEGADO - PERMISSAO]", {
      usuario_id: usuario.id || null,
      usuario: usuario.usuario || null,
      nome: usuario.nome || null,
      perfil: usuario.perfil || null,
      equipe: usuario.equipe || null,
      rota: req.originalUrl,
      metodo: req.method,
      ip: req.ip,
      permissao_exigida: permissao,
      permissoes_usuario: permissoes,
      data_hora: new Date().toISOString()
    });

    return res.status(403).json({
      erro: true,
      mensagem: "Você não possui permissão para esta operação."
    });
  };
}

function responderErroInterno(req, res, erro, contexto = "Erro interno") {
  const codigoErro = `ERR-${Date.now()}-${Math.random()
    .toString(36)
    .slice(2, 8)
    .toUpperCase()}`;

  console.error(`[${codigoErro}] ${contexto}`, {
    usuario_id: req.session?.usuario?.id || null,
    usuario: req.session?.usuario?.usuario || null,
    perfil: req.session?.usuario?.perfil || null,
    metodo: req.method,
    rota: req.originalUrl,
    mensagem: erro?.message || null,
    status_externo: erro?.response?.status || null,
    retorno_externo: erro?.response?.data || null,
    stack: erro?.stack || null
  });

  return res.status(500).json({
    erro: true,
    mensagem: "Não foi possível concluir a operação.",
    codigo: codigoErro
  });
}

async function buscarUsuarioAlvoProtegido(req, res) {
  const usuarioLogado = req.session?.usuario;
  const usuarioAlvoId = Number(req.params.id);

  const [rows] = await db.query(
    `
    SELECT id, usuario, nome, perfil, ativo
    FROM usuarios_dashboard
    WHERE id = ?
    LIMIT 1
    `,
    [usuarioAlvoId]
  );

  if (!rows.length) {
    res.status(404).json({
      erro: true,
      mensagem: "Usuário não encontrado."
    });

    return null;
  }

  const usuarioAlvo = rows[0];

  if (
    usuarioAlvo.perfil === "super_admin" &&
    usuarioLogado?.perfil !== "super_admin"
  ) {
    console.warn("[TENTATIVA DE ALTERAR SUPER ADMIN]", {
      usuario_executor: usuarioLogado?.usuario || null,
      perfil_executor: usuarioLogado?.perfil || null,
      usuario_alvo: usuarioAlvo.usuario,
      usuario_alvo_id: usuarioAlvo.id,
      metodo: req.method,
      rota: req.originalUrl,
      ip: req.ip,
      data_hora: new Date().toISOString()
    });

    res.status(403).json({
      erro: true,
      mensagem: "Somente outro superadministrador pode alterar um superadministrador."
    });

    return null;
  }

  return usuarioAlvo;
}


// TESTE API PIPER RUN //

const {
  buscarDeals
} = require("./integracoes/piperun/client");

const {
  transformarListaDeals
} = require("./integracoes/piperun/service");

const {
  criarSincronizadorPiperun
} = require("./integracoes/piperun/sync");

const {
  criarAgendadorPiperun
} = require("./integracoes/piperun/scheduler");

const {
  criarRotasPiperun
} = require("./integracoes/piperun/routes");

const {
  criarSincronizadorInviabilidade
} = require("./integracoes/inviabilidade/sync");

const {
  criarRotasInviabilidade
} = require("./integracoes/inviabilidade/routes");

const {
  criarSincronizadorInviabilidadeIXC
} = require("./integracoes/inviabilidade/ixc-sync");

const piperunSync = criarSincronizadorPiperun(db);

const inviabilidadeSync =
  criarSincronizadorInviabilidade(db);

async function sincronizarPiperunCompleto() {
  const resultadoPiperun =
    await piperunSync.sincronizarPerdidos();

  const resultadoInviabilidade =
    await inviabilidadeSync.sincronizarPiperun();

  console.log(
    "[INVIABILIDADE] Sincronização concluída.",
    resultadoInviabilidade
  );

  return {
    ...resultadoPiperun,
    inviabilidade: resultadoInviabilidade
  };
}

const piperunScheduler = criarAgendadorPiperun({
  sincronizarPerdidos: sincronizarPiperunCompleto,
  intervaloMs: 10 * 60 * 1000,
  atrasoInicialMs: 30 * 1000
});

const piperunRoutes = criarRotasPiperun({
  db,
  exigirLogin,
  exigirPermissao,
  responderErroInterno
});

const inviabilidadeRoutes =
  criarRotasInviabilidade({
    db,
    exigirLogin,
    exigirPermissao,
    responderErroInterno
  });

// FIM DO CÓDIGO DO PIPER //


function limparDocumento(valor) {
  return String(valor || "").replace(/\D/g, "");
}

function primeirosDigitosDocumento(valor, tamanho = 6) {
  return limparDocumento(valor).slice(0, tamanho);
}

function normalizarEmail(valor) {
  return String(valor || "").trim().toLowerCase();
}

function podeGerenciarPortalCliente(req) {
  const usuario = req.session?.usuario || {};
  const permissoes = usuario.permissoes || [];

  return (
    usuario.perfil === "super_admin" ||
    usuario.perfil === "gerencial" ||
    usuario.perfil === "backoffice" ||
    usuario.perfil === "supervisao_midia" ||
    permissoes.includes("gerenciar_portal_cliente")
  );
}

async function buscarClientePortalPorEmailDocumento(email, documentoParcial) {
  const emailNormalizado = normalizarEmail(email);
  const docParcial = limparDocumento(documentoParcial);

  if (!emailNormalizado || docParcial.length < 6) {
    return null;
  }

  const retorno = await buscar(
    "cliente",
    "cliente.email",
    emailNormalizado,
    "20"
  );

  const clientes = retorno.registros || [];

  return clientes.find(cliente => {
    const emailCliente = normalizarEmail(cliente.email || cliente.email_cobranca || "");
    const documentoCliente = primeirosDigitosDocumento(
      cliente.cnpj_cpf || cliente.cpf_cnpj || cliente.cpf || cliente.cnpj || ""
    );

    return (
      emailCliente === emailNormalizado &&
      documentoCliente === docParcial.slice(0, 6)
    );
  }) || null;
}

async function buscarInstalacoesPendentesPortal(clienteId) {
  const retorno = await buscar(
    "su_oss_chamado",
    "su_oss_chamado.id_cliente",
    String(clienteId),
    "100"
  );

  const ordens = retorno.registros || [];

  return ordens
    .filter(os => {
      const status = String(os.status || "");
      const assunto = String(os.id_assunto || "");

      return (
        status !== "F" &&
        ["137", "599", "591", "247", "2"].includes(assunto)
      );
    })
    .map(os => ({
      os_id: os.id,
      contrato_id: os.id_contrato_kit || os.id_contrato || os.contrato || null,
      assunto_id: os.id_assunto,
      status: os.status,
      data_abertura: os.data_abertura || os.data_inicio || null,
      endereco: os.endereco || os.endereco_padrao_cliente || null,
      bairro: os.bairro || null,
      cidade: os.cidade || null
    }));
}

app.post("/api/portal-cliente/login", limitadorLoginPortal, async (req, res) => {
  try {
    const { email, documento } = req.body || {};

    const cliente = await buscarClientePortalPorEmailDocumento(email, documento);

    if (!cliente) {
      return res.status(401).json({
        erro: true,
        mensagem: "Cliente não localizado. Confira o e-mail e os 6 primeiros dígitos do CPF/CNPJ."
      });
    }

    req.session.portalCliente = {
      cliente_ixc_id: String(cliente.id),
      nome: cliente.razao || cliente.nome || cliente.fantasia || "Cliente",
      email: normalizarEmail(cliente.email || email),
      documento_parcial: limparDocumento(documento).slice(0, 6),
      telefone: cliente.telefone_celular || cliente.fone || cliente.telefone || null,
      cidade: cliente.cidade || null,
      bairro: cliente.bairro || null,
      endereco: cliente.endereco || null
    };

    return res.json({
      sucesso: true,
      cliente: req.session.portalCliente
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});



app.get("/api/portal-cliente/me", async (req, res) => {
  const cliente = req.session?.portalCliente;

  if (!cliente) {
    return res.status(401).json({
      erro: true,
      mensagem: "Sessão do cliente não encontrada."
    });
  }

  return res.json({
    sucesso: true,
    cliente
  });
});

app.post("/api/portal-cliente/logout", async (req, res) => {
  if (req.session) {
    delete req.session.portalCliente;
  }

  return res.json({
    sucesso: true
  });
});

app.get("/api/portal-cliente/minhas-instalacoes", async (req, res) => {
  try {
    const cliente = req.session?.portalCliente;

    if (!cliente) {
      return res.status(401).json({
        erro: true,
        mensagem: "Faça login novamente."
      });
    }

    const instalacoes = await buscarInstalacoesPendentesPortal(cliente.cliente_ixc_id);

    const [solicitacoes] = await db.query(
      `
      SELECT *
      FROM portal_cliente_agendamentos
      WHERE cliente_ixc_id = ?
      ORDER BY criado_em DESC
      `,
      [cliente.cliente_ixc_id]
    );

    return res.json({
      sucesso: true,
      cliente,
      instalacoes,
      solicitacoes
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

app.post("/api/portal-cliente/agendamento", async (req, res) => {
  try {
    const cliente = req.session?.portalCliente;

    if (!cliente) {
      return res.status(401).json({
        erro: true,
        mensagem: "Faça login novamente."
      });
    }

    const {
      os_id,
      contrato_id,
      data_solicitada,
      turno_solicitado,
      observacao_cliente
    } = req.body || {};

    if (!data_solicitada || !turno_solicitado) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe a data e o turno desejado."
      });
    }

    if (!["MANHA", "TARDE"].includes(String(turno_solicitado))) {
      return res.status(400).json({
        erro: true,
        mensagem: "Turno inválido."
      });
    }

    const hoje = new Date();
    hoje.setHours(0, 0, 0, 0);

    const dataEscolhida = new Date(`${data_solicitada}T00:00:00`);

    if (dataEscolhida < hoje) {
      return res.status(400).json({
        erro: true,
        mensagem: "Escolha uma data futura."
      });
    }


    const dataSolicitadaObj = new Date(`${data_solicitada}T00:00:00`);
    const hojeBase = new Date();
    hojeBase.setHours(0, 0, 0, 0);

    const amanha = new Date(hojeBase);
    amanha.setDate(amanha.getDate() + 1);

    const limite = new Date(hojeBase);
    limite.setDate(limite.getDate() + 15);

    if (isNaN(dataSolicitadaObj.getTime())) {
      return res.status(400).json({
        erro: true,
        mensagem: "Data solicitada inválida."
      });
    }

    if (dataSolicitadaObj < amanha) {
      return res.status(400).json({
        erro: true,
        mensagem: "Escolha uma data a partir de amanhã."
      });
    }

    if (dataSolicitadaObj > limite) {
      return res.status(400).json({
        erro: true,
        mensagem: "Escolha uma data dentro dos próximos 15 dias."
      });
    }

    if (dataSolicitadaObj.getDay() === 0) {
      return res.status(400).json({
        erro: true,
        mensagem: "Não realizamos instalações aos domingos."
      });
    }

    await db.query(
      `
      INSERT INTO portal_cliente_agendamentos
        (
          cliente_ixc_id,
          contrato_id,
          os_id,
          cliente_nome,
          email,
          documento_parcial,
          telefone,
          cidade,
          bairro,
          endereco,
          data_solicitada,
          turno_solicitado,
          status,
          observacao_cliente
        )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'SOLICITADO', ?)
      `,
      [
        cliente.cliente_ixc_id,
        contrato_id || null,
        os_id || null,
        cliente.nome || null,
        cliente.email || null,
        cliente.documento_parcial || null,
        cliente.telefone || null,
        cliente.cidade || null,
        cliente.bairro || null,
        cliente.endereco || null,
        data_solicitada,
        turno_solicitado,
        observacao_cliente || null
      ]
    );

    return res.json({
      sucesso: true,
      mensagem: "Solicitação enviada com sucesso. Nossa equipe irá validar a disponibilidade."
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

app.get("/api/portal-cliente/solicitacoes", exigirLogin, async (req, res) => {
  try {
    if (!podeGerenciarPortalCliente(req)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Você não tem permissão para gerenciar solicitações do portal."
      });
    }

    const status = req.query.status || "SOLICITADO";

    const [solicitacoes] = await db.query(
      `
      SELECT *
      FROM portal_cliente_agendamentos
      WHERE status = ?
      ORDER BY data_solicitada ASC, criado_em ASC
      `,
      [status]
    );

    return res.json({
      sucesso: true,
      solicitacoes
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});


function montarUsuarioSeguro(usuario) {
  return {
    nome: usuario.nome,
    perfil: usuario.perfil,
    equipe: usuario.equipe,
    vendedor_id: usuario.vendedor_id,
    permissoes: usuario.permissoes
  };
}

      function temPermissao(usuario, permissao) {
        return usuario?.permissoes?.includes(permissao);
      }
          function vendedorPermitido(usuario, vendedorId) {
            if (!usuario) return false;

            if (
              usuario.perfil === "super_admin" ||
              usuario.perfil === "gerencial" ||
              usuario.perfil === "operacional"
            ) {
              return true;
            }

            vendedorId = String(vendedorId || "");

            const permissoes = Array.isArray(usuario.permissoes)
              ? usuario.permissoes
              : [];

            if (permissoes.includes("ver_todos_vendedores")) {
              return true;
            }

            if (permissoes.includes("ver_equipe")) {
              const equipe = equipesComerciais[usuario.equipe] || [];
              return equipe.includes(vendedorId);
            }

            if (permissoes.includes("ver_proprio_vendedor")) {
              return String(usuario.vendedor_id) === vendedorId;
            }

            return false;
          }

            function podeGerenciarUsuarios(usuario) {
              return usuario?.perfil === "super_admin" || temPermissao(usuario, "gerenciar_usuarios");
            }

            function podeGerenciarMetas(usuario) {
              return (
                usuario?.perfil === "super_admin" ||
                usuario?.perfil === "gerencial" ||
                temPermissao(usuario, "gerenciar_metas")
              );
            }

app.post("/api/login", limitadorLoginSistema, async (req, res) => {  
  try {
    const { usuario, senha } = req.body || {};

    if (!usuario || !senha) {
      return res.status(400).json({
        erro: true,
        mensagem: "Usuário e senha são obrigatórios."
      });
    }

    const userBanco = await autenticarUsuario(usuario, senha);

    if (userBanco) {
      await db.query(
        "UPDATE usuarios_dashboard SET ultimo_login = NOW() WHERE id = ?",
        [userBanco.id]
      );

      req.session.logado = true;
          req.session.usuario = {
            id: userBanco.id,
            usuario: userBanco.usuario,
            nome: userBanco.nome,
            perfil: userBanco.perfil,
            equipe: userBanco.equipe,
            vendedor_id: userBanco.vendedor_id,
            foto_url: userBanco.foto_url || null,
            colaborador_ixc_id: userBanco.colaborador_ixc_id || null,
            permissoes: userBanco.permissoes,
            origem: "banco"
          };

      return res.json({
        sucesso: true,
        usuario: req.session.usuario
      });
    }

    const userLegado = usuariosDashboard[usuario];

    if (userLegado && userLegado.senha === senha) {
      req.session.logado = true;
      req.session.usuario = {
        ...montarUsuarioSeguro(userLegado),
        usuario,
        origem: "usuarios_js"
      };

      return res.json({
        sucesso: true,
        usuario: req.session.usuario
      });
    }

    if (
      usuario === process.env.DASHBOARD_USER &&
      senha === process.env.DASHBOARD_PASS
    ) {
      req.session.logado = true;
      req.session.usuario = {
        usuario,
        nome: "Administrador",
        perfil: "super_admin",
        origem: "env"
      };

      return res.json({
        sucesso: true,
        usuario: req.session.usuario
      });
    }

    return res.status(401).json({
      erro: true,
      mensagem: "Usuário ou senha inválidos."
    });

  } catch (erro) {
    console.error("Erro login:", erro);

    return res.status(500).json({
      erro: true,
      mensagem: "Erro interno no login."
    });
  }
});

app.use("/api", (req, res, next) => {
  if (
    req.path === "/login" ||
    req.path.startsWith("/portal-cliente/")
  ) {
    return next();
  }

  if (req.session?.logado) return next();

  return res.status(401).json({
    erro: true,
    mensagem: "Acesso não autorizado."
  });
});

      app.post("/api/alterar-senha", exigirLogin, async (req, res) => {
        try {
          const { senhaAtual, novaSenha, confirmarNovaSenha } = req.body || {};
          const usuarioId = req.session.usuario?.id;

          if (!usuarioId) {
            return res.status(401).json({
              erro: true,
              mensagem: "Usuário não identificado."
            });
          }

          if (!senhaAtual || !novaSenha || !confirmarNovaSenha) {
            return res.status(400).json({
              erro: true,
              mensagem: "Preencha todos os campos."
            });
          }

          if (novaSenha !== confirmarNovaSenha) {
            return res.status(400).json({
              erro: true,
              mensagem: "A confirmação da nova senha não confere."
            });
          }

          if (novaSenha.length < 8) {
            return res.status(400).json({
              erro: true,
              mensagem: "A nova senha precisa ter pelo menos 8 caracteres."
            });
          }

          const [rows] = await db.query(
            "SELECT id, senha_hash FROM usuarios_dashboard WHERE id = ? AND ativo = 1 LIMIT 1",
            [usuarioId]
          );

          if (!rows.length) {
            return res.status(404).json({
              erro: true,
              mensagem: "Usuário não encontrado."
            });
          }

          const senhaAtualValida = await bcrypt.compare(senhaAtual, rows[0].senha_hash);

          if (!senhaAtualValida) {
            return res.status(400).json({
              erro: true,
              mensagem: "Senha atual incorreta."
            });
          }

          const novaSenhaHash = await bcrypt.hash(novaSenha, 10);

          await db.query(
            `
            UPDATE usuarios_dashboard
            SET senha_hash = ?,
                primeiro_acesso = 0,
                ultima_alteracao_senha = NOW()
            WHERE id = ?
            `,
            [novaSenhaHash, usuarioId]
          );

          req.session.usuario.primeiro_acesso = 0;

          res.json({
            sucesso: true,
            mensagem: "Senha alterada com sucesso."
          });

        } catch (erro) {
          res.status(500).json({
            erro: true,
            mensagem: erro.message
          });
        }
      });

app.get("/api/usuarios", exigirLogin, exigirPermissao("gerenciar_usuarios"), async (req, res) => {
        try {
          const usuarioLogado = req.session.usuario;

          if (!podeGerenciarUsuarios(usuarioLogado)) {
            return res.status(403).json({
              erro: true,
              mensagem: "Acesso negado."
            });
          }

          const [usuarios] = await db.query(`
            SELECT
              id,
              usuario,
              nome,
              perfil,
              equipe,
              vendedor_id,
              ativo,
              ultimo_login,
              criado_em,
              primeiro_acesso,
              ultima_alteracao_senha
            FROM usuarios_dashboard
            ORDER BY id ASC
          `);

          const [permissoes] = await db.query(`
            SELECT usuario_id, permissao
            FROM permissoes_usuario
          `);

          const usuariosComPermissoes = usuarios.map(user => ({
            ...user,
            permissoes: permissoes
              .filter(p => Number(p.usuario_id) === Number(user.id))
              .map(p => p.permissao)
          }));

          res.json({
            total: usuariosComPermissoes.length,
            usuarios: usuariosComPermissoes
          });

      } catch (erro) {
        return responderErroInterno(
          req,
          res,
          erro,
          "Erro ao listar usuários"
        );
      }
      });

app.patch("/api/usuarios/:id/status", exigirLogin, exigirPermissao("gerenciar_usuarios"), async (req, res) => {
    try {
      const usuarioLogado = req.session.usuario;

      if (!podeGerenciarUsuarios(usuarioLogado)) {
        return res.status(403).json({
          erro: true,
          mensagem: "Acesso negado."
        });
      }

      const { ativo } = req.body;
      const usuarioAlvoId = Number(req.params.id);

      if (
        usuarioAlvoId === Number(usuarioLogado?.id) &&
        !Boolean(ativo)
      ) {
        return res.status(400).json({
          erro: true,
          mensagem: "Você não pode inativar o próprio usuário."
        });
      }

      const [usuariosAlvo] = await db.query(
        `
        SELECT id, usuario, nome, perfil, ativo
        FROM usuarios_dashboard
        WHERE id = ?
        LIMIT 1
        `,
        [usuarioAlvoId]
      );

      if (!usuariosAlvo.length) {
        return res.status(404).json({
          erro: true,
          mensagem: "Usuário não encontrado."
        });
      }

      const usuarioAlvo = usuariosAlvo[0];

      if (
        usuarioAlvo.perfil === "super_admin" &&
        usuarioLogado?.perfil !== "super_admin"
      ) {
        console.warn("[TENTATIVA DE ALTERAR SUPER ADMIN]", {
          usuario_executor: usuarioLogado?.usuario || null,
          perfil_executor: usuarioLogado?.perfil || null,
          usuario_alvo: usuarioAlvo.usuario,
          usuario_alvo_id: usuarioAlvo.id,
          acao: Boolean(ativo) ? "ATIVAR" : "INATIVAR",
          rota: req.originalUrl,
          ip: req.ip,
          data_hora: new Date().toISOString()
        });

        return res.status(403).json({
          erro: true,
          mensagem: "Somente outro superadministrador pode alterar o status de um superadministrador."
        });
      }

      await db.query(
        "UPDATE usuarios_dashboard SET ativo = ? WHERE id = ?",
        [Boolean(ativo) ? 1 : 0, usuarioAlvoId]
      );

      return res.json({
        sucesso: true,
        mensagem: "Status do usuário atualizado com sucesso."
      });

    } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao alterar status do usuário"
      );
    }
  }
);

app.patch("/api/usuarios/:id", exigirLogin,  exigirPermissao("gerenciar_usuarios"), async (req, res) => {
  try {
    const usuarioLogado = req.session.usuario;

    if (!podeGerenciarUsuarios(usuarioLogado)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso negado."
      });
    }

    const { id } = req.params;
    const { nome, perfil, equipe, vendedor_id } = req.body || {};

    const usuarioAlvo = await buscarUsuarioAlvoProtegido(req, res);

      if (!usuarioAlvo) {
        return;
      }

    if (
      perfil === "super_admin" &&
      req.session.usuario?.perfil !== "super_admin"
    ) {
      return res.status(403).json({
        erro: true,
        mensagem: "Somente um superadministrador pode definir este perfil."
      });
    }

    if (
      Number(id) === Number(req.session.usuario?.id) &&
      perfil !== req.session.usuario?.perfil
    ) {
      return res.status(400).json({
        erro: true,
        mensagem: "Você não pode alterar o próprio perfil."
      });
    }

    if (!nome || !perfil) {
      return res.status(400).json({
        erro: true,
        mensagem: "Nome e perfil são obrigatórios."
      });
    }

    await db.query(
      `
      UPDATE usuarios_dashboard
      SET nome = ?, perfil = ?, equipe = ?, vendedor_id = ?
      WHERE id = ?
      `,
      [
        nome,
        perfil,
        equipe || null,
        vendedor_id || null,
        id
      ]
    );

    res.json({
      sucesso: true,
      mensagem: "Usuário atualizado com sucesso."
    });

  } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao editar usuário"
      );
  }
});

app.patch("/api/usuarios/:id/permissoes", exigirLogin,   exigirPermissao("gerenciar_usuarios"), async (req, res) => {
  try {
    const usuarioLogado = req.session.usuario;

    if (!podeGerenciarUsuarios(usuarioLogado)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso negado."
      });
    }

    const { id } = req.params;
    const { permissoes } = req.body || {};

    const usuarioAlvo = await buscarUsuarioAlvoProtegido(req, res);

    if (!usuarioAlvo) {
      return;
    }

    
    if (
  Number(id) === Number(req.session.usuario?.id) &&
        req.session.usuario?.perfil === "super_admin"
      ) {
        return res.status(400).json({
          erro: true,
          mensagem: "O superadministrador não pode alterar as próprias permissões por esta rota."
        });
      }

      if (Number(id) === Number(req.session.usuario?.id)) {
  return res.status(400).json({
    erro: true,
    mensagem: "Você não pode alterar as próprias permissões."
  });
}

    if (!Array.isArray(permissoes)) {
      return res.status(400).json({
        erro: true,
        mensagem: "Permissões inválidas."
      });
    }

    await db.query(
      "DELETE FROM permissoes_usuario WHERE usuario_id = ?",
      [id]
    );

    const permissoesUnicas = [...new Set(permissoes)];

    for (const permissao of permissoesUnicas) {
      await db.query(
        "INSERT INTO permissoes_usuario (usuario_id, permissao) VALUES (?, ?)",
        [id, permissao]
      );
    }

    res.json({
      sucesso: true,
      mensagem: "Permissões atualizadas com sucesso."
    });

  } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao alterar permissões do usuário"
      );
  }
});


  app.post("/api/usuarios", exigirLogin,   exigirPermissao("gerenciar_usuarios"), async (req, res) => {
  try {
    const usuarioLogado = req.session.usuario;

    if (!podeGerenciarUsuarios(usuarioLogado)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso negado."
      });
    }

    const {
      usuario,
      nome,
      senha,
      perfil,
      equipe,
      vendedor_id,
      permissoes
    } = req.body || {};

    if (
  perfil === "super_admin" &&
      req.session.usuario?.perfil !== "super_admin"
    ) {
      return res.status(403).json({
        erro: true,
        mensagem: "Somente um superadministrador pode criar outro superadministrador."
      });
    }

    if (!usuario || !nome || !senha || !perfil) {
      return res.status(400).json({
        erro: true,
        mensagem: "Usuário, nome, senha e perfil são obrigatórios."
      });
    }

    if (senha.length < 8) {
      return res.status(400).json({
        erro: true,
        mensagem: "A senha precisa ter pelo menos 8 caracteres."
      });
    }

    const permissoesFinais = Array.isArray(permissoes)
      ? [...permissoes]
      : [];

    if (
      perfil === "vendedor" &&
      !permissoesFinais.includes("ver_proprio_vendedor")
    ) {
      permissoesFinais.push("ver_proprio_vendedor");
    }

    if (perfil === "reversao_churn") {
      if (!permissoesFinais.includes("ver_ranking_churn")) {
        permissoesFinais.push("ver_ranking_churn");
      }

      if (!permissoesFinais.includes("ver_proprio_churn")) {
        permissoesFinais.push("ver_proprio_churn");
      }
    }

    const senhaHash = await bcrypt.hash(senha, 10);

    const [resultado] = await db.query(
      `
      INSERT INTO usuarios_dashboard
        (usuario, nome, senha_hash, perfil, equipe, vendedor_id, ativo, primeiro_acesso)
      VALUES (?, ?, ?, ?, ?, ?, 1, 1)
      `,
      [
        usuario.trim(),
        nome.trim(),
        senhaHash,
        perfil,
        equipe || null,
        vendedor_id || null
      ]
    );

    const usuarioId = resultado.insertId;

    const permissoesUnicas = [...new Set(permissoesFinais)];

    for (const permissao of permissoesUnicas) {
      await db.query(
        "INSERT INTO permissoes_usuario (usuario_id, permissao) VALUES (?, ?)",
        [usuarioId, permissao]
      );
    }

    return res.json({
      sucesso: true,
      mensagem: "Usuário cadastrado com sucesso.",
      usuario_id: usuarioId
    });

  } catch (erro) {
    if (erro.code === "ER_DUP_ENTRY") {
      return res.status(400).json({
        erro: true,
        mensagem: "Já existe um usuário com esse login."
      });
    }

      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao cadastrar usuário"
      );
  }
});

app.patch("/api/usuarios/:id/resetar-senha", exigirLogin,   exigirPermissao("gerenciar_usuarios"), async (req, res) => {
  try {
    const usuarioLogado = req.session.usuario;

    if (!podeGerenciarUsuarios(usuarioLogado)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso negado."
      });
    }

    const usuarioAlvo = await buscarUsuarioAlvoProtegido(req, res);

    if (!usuarioAlvo) {
      return;
    }

    const { id } = req.params;
    const { novaSenha } = req.body || {};

    if (!novaSenha || novaSenha.length < 8) {
      return res.status(400).json({
        erro: true,
        mensagem: "A nova senha precisa ter pelo menos 8 caracteres."
      });
    }

    const senhaHash = await bcrypt.hash(novaSenha, 10);

    await db.query(
      `
      UPDATE usuarios_dashboard
      SET
        senha_hash = ?,
        primeiro_acesso = 1,
        ultima_alteracao_senha = NOW()
      WHERE id = ?
      `,
      [senhaHash, id]
    );

    res.json({
      sucesso: true,
      mensagem: "Senha redefinida com sucesso."
    });

  } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao resetar senha do usuário"
      );
  }
});


app.get("/api/me", exigirLogin, async (req, res) => {
  try {
    const usuarioSessao = req.session.usuario;

    if (!usuarioSessao?.id) {
      return res.json({
        logado: true,
        usuario: usuarioSessao
      });
    }

    const [rows] = await db.query(
      `
      SELECT foto_url,  colaborador_ixc_id
      FROM usuarios_dashboard
      WHERE id = ?
      LIMIT 1
      `,
      [usuarioSessao.id]
    );

    if (rows.length) {
      req.session.usuario.foto_url = rows[0].foto_url || null;
      req.session.usuario.colaborador_ixc_id = rows[0].colaborador_ixc_id || null;
    }

    res.json({
      logado: true,
      usuario: req.session.usuario
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});


app.use(express.static(path.join(__dirname, "public"), {
  index: false
}));


let confirmacoesOS = {
  atual: {},
  historico: []
};

let listaConfirmacaoAtual = [];


app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));

const uploadFotoUsuario = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, path.join(__dirname, "public/uploads"));
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname || ".png");
      cb(null, `usuario-${req.session.usuario.id}-${Date.now()}${ext}`);
    }
  })
});


app.post("/api/me/foto", exigirLogin, uploadFotoUsuario.single("foto"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        erro: true,
        mensagem: "Nenhuma foto enviada."
      });
    }

    const fotoUrl = `/uploads/${req.file.filename}`;

    await db.query(
      "UPDATE usuarios_dashboard SET foto_url = ? WHERE id = ?",
      [fotoUrl, req.session.usuario.id]
    );

    req.session.usuario.foto_url = fotoUrl;

    return res.json({
      sucesso: true,
      foto_url: fotoUrl
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});


app.get("/", (req, res) => {
  if (!req.session?.logado) {
    return res.sendFile(
      path.join(__dirname, "public", "login.html")
    );
  }

  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

app.get("/login", (req, res) => {
  if (req.session?.logado) {
    return res.redirect("/");
  }

  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post("/api/logout", exigirLogin, (req, res) => {
  req.session.destroy((erro) => {
    if (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao encerrar sessão"
      );
    }

      res.clearCookie(nomeCookieSessao, {
        httpOnly: true,
        sameSite: "lax",
        secure:
          process.env.NODE_ENV === "production"
      });

    return res.json({
      sucesso: true,
      mensagem: "Sessão encerrada com sucesso."
    });
  });
});


const PORT = process.env.PORT || 3000;

const assuntosMonitorados = {
  "137": "ATIVAÇÃO FTTH",
  "599": "REATIVAÇÃO 90 DIAS",
  "591": "REATIVAÇÃO COMERCIAL",
  "247": "ATIVAÇÃO FTTH - FIBRASIL"
};

const tokenBase64 = Buffer.from(process.env.IXC_TOKEN).toString("base64");

const api = axios.create({
  baseURL: process.env.IXC_URL,
  headers: {
    Authorization: `Basic ${tokenBase64}`,
    "Content-Type": "application/json",
    ixcsoft: "listar"
  }
});

async function buscar(endpoint, qtype, query, rp = "50") {
  const params = {
    qtype,
    query,
    oper: "=",
    page: "1",
    rp,
    sortname: "id",
    sortorder: "desc"
  };

  const response = await api.post(`/${endpoint}`, params);
  return response.data;
}

async function buscarComFiltros(endpoint, filtros = [], rp = "500") {
  const params = {
    page: "1",
    rp,
    sortname: "id",
    sortorder: "desc"
  };

  filtros.forEach((filtro, index) => {
    params[`qtype${index + 1}`] = filtro.qtype;
    params[`query${index + 1}`] = filtro.query;
    params[`oper${index + 1}`] = filtro.oper || "=";
  });

  const response = await api.post(`/${endpoint}`, params);
  return response.data;
}

function aguardarIXC(ms) {
  return new Promise(resolve => {
    setTimeout(resolve, ms);
  });
}

function normalizarTelefoneIXC(valor) {
  const telefone = String(valor || "")
    .replace(/\D/g, "");

  if (!telefone) return "";

  // Remove código do Brasil quando houver.
  if (
    telefone.length > 11 &&
    telefone.startsWith("55")
  ) {
    return telefone.slice(2);
  }

  return telefone;
}

function coordenadaNumericaIXC(latitude, longitude) {
  const lat = Number(latitude);
  const lng = Number(longitude);

  return (
    Number.isFinite(lat) &&
    Number.isFinite(lng) &&
    lat !== 0 &&
    lng !== 0
  );
}

function coordenadaOperacionalIXC(latitude, longitude) {
  const lat = Number(latitude);
  const lng = Number(longitude);

  if (!coordenadaNumericaIXC(lat, lng)) {
    return false;
  }

  /*
   * Faixa ampla de diagnóstico.
   * Não significa que toda coordenada dentro dela seja atendida.
   */
  return (
    lat >= -5 &&
    lat <= 0.5 &&
    lng >= -51 &&
    lng <= -46
  );
}

function obterMesRegistroIXC(dataCadastro) {
  const valor = String(dataCadastro || "").trim();

  const correspondencia =
    valor.match(/^(\d{4})-(\d{2})/);

  if (!correspondencia) {
    return "SEM_DATA";
  }

  return `${correspondencia[1]}-${correspondencia[2]}`;
}

async function buscarPaginaContatosIXC({
  pagina,
  registrosPorPagina
}) {
  const params = {
    qtype: "contato.status_viabilidade",
    query: "N",
    oper: "=",
    page: String(pagina),
    rp: String(registrosPorPagina),
    sortname: "id",
    sortorder: "desc"
  };

  const response = await api.post(
    "/contato",
    params
  );

  const retorno = response.data || {};

  if (retorno.type === "error") {
    throw new Error(
      retorno.message ||
      "Erro ao consultar recurso contato."
    );
  }

  return retorno;
}

const sincronizadorInviabilidadeIXC =
  criarSincronizadorInviabilidadeIXC({
    db,

    buscarPaginaIXC:
      buscarPaginaContatosIXC,

    buscarCidadeIXCCache
  });

async function buscarContatosInviaveisIXCPaginado({
  registrosPorPagina = 500,
  limitePaginas = 20,
  intervaloMs = 250
} = {}) {
  const todos = [];
  let pagina = 1;
  let totalIXC = 0;
  let totalPaginas = 1;

  while (
    pagina <= totalPaginas &&
    pagina <= limitePaginas
  ) {

  const retorno =
    await buscarPaginaContatosIXC({
      pagina,
      registrosPorPagina
    });

    const registros = Array.isArray(
      retorno.registros
    )
      ? retorno.registros
      : [];

    if (pagina === 1) {
      totalIXC = Number(retorno.total || 0);

      totalPaginas = Math.max(
        Math.ceil(
          totalIXC / registrosPorPagina
        ),
        1
      );
    }

    todos.push(...registros);

    console.log(
      `[IXC INVIABILIDADE] Página ${pagina}/${totalPaginas} ` +
      `- recebidos: ${registros.length}`
    );

    /*
     * Evita repetição infinita caso o IXC
     * devolva uma página vazia.
     */
    if (!registros.length) {
      break;
    }

    pagina += 1;

    if (
      pagina <= totalPaginas &&
      intervaloMs > 0
    ) {
      await aguardarIXC(intervaloMs);
    }
  }

  return {
    total_ixc: totalIXC,
    paginas_previstas: totalPaginas,
    paginas_processadas: pagina - 1,
    consulta_completa:
      pagina > totalPaginas,
    registros: todos
  };
}

registrarDebugGet(
  "/api/debug/ixc/sincronizar-inviabilidades",
  async (req, res) => {
    try {
      const resultado =
        await sincronizadorInviabilidadeIXC
          .sincronizarIXC({
            registrosPorPagina: 500,
            limitePaginas: 20,
            intervaloMs: 250
          });

      return res.json({
        sucesso: true,
        resultado
      });
    } catch (erro) {
      console.error(
        "[IXC INVIABILIDADE] Erro na sincronização:",
        erro.response?.data ||
        erro.message
      );

      return res.status(500).json({
        sucesso: false,
        mensagem:
          "Erro ao sincronizar inviabilidades do IXC.",
        detalhe:
          erro.response?.data ||
          erro.message
      });
    }
  }
);

app.get("/api/inviabilidades", exigirLogin, async (req, res) => {
  try {
    const origem = String(
      req.query.origem || ""
    )
      .trim()
      .toUpperCase();

    const status = String(
      req.query.status || ""
    )
      .trim()
      .toUpperCase();

    const cidade = String(
      req.query.cidade || ""
    ).trim();

    const bairro = String(
      req.query.bairro || ""
    ).trim();

    const busca = String(
      req.query.busca || ""
    ).trim();

    const paginaInformada =
      Number(req.query.pagina || 1);

    const limiteInformado =
      Number(req.query.limite || 250);

    const pagina =
      Number.isInteger(paginaInformada) &&
      paginaInformada > 0
        ? paginaInformada
        : 1;

    /*
     * Proteção para o front não solicitar milhares
     * de registros em uma única requisição.
     */
    const limite = Math.min(
      Math.max(
        Number.isInteger(limiteInformado)
          ? limiteInformado
          : 250,
        50
      ),
      500
    );

    const offset =
      (pagina - 1) * limite;

    const condicoes = [];
    const valores = [];

    if (
      origem &&
      ["IXC", "PIPERUN"].includes(origem)
    ) {
      condicoes.push(
        "origem = ?"
      );

      valores.push(origem);
    }

    if (status) {
      condicoes.push(
        "status = ?"
      );

      valores.push(status);
    }

    if (cidade) {
      condicoes.push(
        "cidade = ?"
      );

      valores.push(cidade);
    }

    if (bairro) {
      condicoes.push(
        "bairro = ?"
      );

      valores.push(bairro);
    }

    if (busca) {
      condicoes.push(`
        (
          cliente LIKE ?
          OR endereco LIKE ?
          OR numero LIKE ?
          OR referencia LIKE ?
          OR motivo_nome LIKE ?
        )
      `);

      const termoBusca =
        `%${busca}%`;

      valores.push(
        termoBusca,
        termoBusca,
        termoBusca,
        termoBusca,
        termoBusca
      );
    }

    const whereSql =
      condicoes.length
        ? `WHERE ${condicoes.join(" AND ")}`
        : "";

        const [
          [[resumo]],
          [origens],
          [statusResumo],
          [[totalFiltrado]],
          [registros],
          [cidades],
          [bairros]
        ] = await Promise.all([
      db.query(`
        SELECT
          COUNT(*) AS total,
          SUM(
            CASE
              WHEN origem = 'IXC'
              THEN 1
              ELSE 0
            END
          ) AS total_ixc,
          SUM(
            CASE
              WHEN origem = 'PIPERUN'
              THEN 1
              ELSE 0
            END
          ) AS total_piperun,
          SUM(
            CASE
              WHEN status = 'ATIVA'
              THEN 1
              ELSE 0
            END
          ) AS total_ativas,
          SUM(
            CASE
              WHEN status <> 'ATIVA'
              THEN 1
              ELSE 0
            END
          ) AS total_nao_ativas,
          COUNT(
            DISTINCT NULLIF(cidade, '')
          ) AS total_cidades
        FROM inviabilidades_mapa
      `),

      db.query(`
        SELECT
          origem,
          COUNT(*) AS total
        FROM inviabilidades_mapa
        GROUP BY origem
        ORDER BY origem
      `),

      db.query(`
        SELECT
          status,
          COUNT(*) AS total
        FROM inviabilidades_mapa
        GROUP BY status
        ORDER BY status
      `),

      db.query(
        `
        SELECT
          COUNT(*) AS total
        FROM inviabilidades_mapa
        ${whereSql}
        `,
        valores
      ),

      db.query(
        `
        SELECT
          id,
          origem,
          origem_id,
          lead_ixc_id,
          cliente,
          motivo_codigo,
          motivo_nome,
          categoria,
          vendedor_nome,
          vendedor_ixc_id,        
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
          sincronizado_em
        FROM inviabilidades_mapa
        ${whereSql}
        ORDER BY
          data_inviabilidade DESC,
          id DESC
        LIMIT ?
        OFFSET ?
        `,
        [
          ...valores,
          limite,
          offset
        ]
      ),

      db.query(`
        SELECT DISTINCT
          cidade
        FROM inviabilidades_mapa
        WHERE cidade IS NOT NULL
          AND cidade <> ''
        ORDER BY cidade
      `),

      db.query(
        `
        SELECT DISTINCT
          bairro
        FROM inviabilidades_mapa
        WHERE bairro IS NOT NULL
          AND bairro <> ''
          ${
            cidade
              ? "AND cidade = ?"
              : ""
          }
        ORDER BY bairro
        `,
        cidade
          ? [cidade]
          : []
      )
    ]);

    const total =
      Number(
        totalFiltrado?.total || 0
      );

    return res.json({
      sucesso: true,

      resumo: {
        total:
          Number(resumo?.total || 0),

        ixc:         
          Number(resumo?.total_ixc || 0),

        piperun:
          Number(
            resumo?.total_piperun || 0
          ),

        ativas:
          Number(
            resumo?.total_ativas || 0
          ),

        nao_ativas:
          Number(
            resumo?.total_nao_ativas || 0
          ),

        cidades:
          Number(
            resumo?.total_cidades || 0
          )
      },

      agrupamentos: {
        origens:
          origens || [],

        status:
          statusResumo || []
      },

      filtros: {
        cidades: (
          cidades || []
        ).map(item => item.cidade),

        bairros: (
          bairros || []
        ).map(item => item.bairro)
      },

      paginacao: {
        pagina,
        limite,
        total,
        total_paginas:
          Math.max(
            Math.ceil(total / limite),
            1
          )
      },

      registros:
        registros || []
    });
  } catch (erro) {
    console.error(
      "[INVIABILIDADES] Erro ao consultar registros:",
      erro
    );

    return res.status(500).json({
      erro: true,
      mensagem:
        "Não foi possível carregar as inviabilidades."
    });
  }
});

registrarDebugGet(
  "/api/debug/ixc/diagnostico-leads-inviaveis",
  async (req, res) => {
    const inicio = Date.now();

    try {
      const registrosPorPagina = Math.min(
        Math.max(
          Number(req.query.rp || 500),
          100
        ),
        500
      );

      const limitePaginas = Math.min(
        Math.max(
          Number(req.query.paginas || 20),
          1
        ),
        20
      );

      const resultado =
        await buscarContatosInviaveisIXCPaginado({
          registrosPorPagina,
          limitePaginas,
          intervaloMs: 250
        });

      const registrosRecebidos =
        resultado.registros;

      /*
       * Mantém apenas registros que realmente
       * representam leads.
       */
      const leads = registrosRecebidos.filter(item =>
        String(item.lead || "")
          .trim()
          .toUpperCase() === "S"
      );

      const resumo = {
        total_recebido: registrosRecebidos.length,
        total_leads: leads.length,

        ativos: 0,
        inativos: 0,

        com_coordenadas_numericas: 0,
        sem_coordenadas: 0,

        coordenadas_operacionais: 0,
        coordenadas_fora_da_area: 0,

        com_cidade_id: 0,
        sem_cidade_id: 0,

        com_bairro: 0,
        sem_bairro: 0,

        com_endereco: 0,
        sem_endereco: 0,

        com_caixa_ftth: 0,
        sem_caixa_ftth: 0
      };

      const porMes = {};
      const porCidadeId = {};
      const porBairro = {};

      const telefones = new Map();
      const coordenadas = new Map();

      const coordenadasSuspeitas = [];

      for (const item of leads) {
        const ativo =
          String(item.ativo || "")
            .trim()
            .toUpperCase();

        if (ativo === "S") {
          resumo.ativos += 1;
        } else {
          resumo.inativos += 1;
        }

        const possuiCoordenada =
          coordenadaNumericaIXC(
            item.latitude,
            item.longitude
          );

        if (possuiCoordenada) {
          resumo.com_coordenadas_numericas += 1;
        } else {
          resumo.sem_coordenadas += 1;
        }

        const coordenadaOperacional =
          coordenadaOperacionalIXC(
            item.latitude,
            item.longitude
          );

        if (coordenadaOperacional) {
          resumo.coordenadas_operacionais += 1;
        } else {
          resumo.coordenadas_fora_da_area += 1;

          if (coordenadasSuspeitas.length < 50) {
            coordenadasSuspeitas.push({
              id: item.id,
              data_cadastro:
                item.data_cadastro,
              cidade_id: item.cidade,
              bairro: item.bairro,
              latitude: item.latitude,
              longitude: item.longitude,
              distancia_caixa:
                item.distancia_caixa_mais_proxima
            });
          }
        }

        const cidadeId =
          String(item.cidade || "").trim();

        if (cidadeId && cidadeId !== "0") {
          resumo.com_cidade_id += 1;

          porCidadeId[cidadeId] =
            (porCidadeId[cidadeId] || 0) + 1;
        } else {
          resumo.sem_cidade_id += 1;
        }

        const bairro =
          String(item.bairro || "").trim();

        if (bairro) {
          resumo.com_bairro += 1;

          porBairro[bairro] =
            (porBairro[bairro] || 0) + 1;
        } else {
          resumo.sem_bairro += 1;
        }

        const endereco =
          String(item.endereco || "").trim();

        if (endereco) {
          resumo.com_endereco += 1;
        } else {
          resumo.sem_endereco += 1;
        }

        const caixa =
          String(item.id_caixa_ftth || "").trim();

        if (caixa && caixa !== "0") {
          resumo.com_caixa_ftth += 1;
        } else {
          resumo.sem_caixa_ftth += 1;
        }

        const mes =
          obterMesRegistroIXC(
            item.data_cadastro
          );

        porMes[mes] =
          (porMes[mes] || 0) + 1;

        const telefone = normalizarTelefoneIXC(
          item.fone_whatsapp ||
          item.fone_celular ||
          item.nome
        );

        if (telefone.length >= 10) {
          if (!telefones.has(telefone)) {
            telefones.set(telefone, []);
          }

          telefones.get(telefone).push(
            String(item.id)
          );
        }

        if (possuiCoordenada) {
          /*
           * Reduz para seis casas para detectar
           * pontos praticamente iguais.
           */
          const chaveCoordenada = [
            Number(item.latitude).toFixed(6),
            Number(item.longitude).toFixed(6)
          ].join(",");

          if (!coordenadas.has(chaveCoordenada)) {
            coordenadas.set(
              chaveCoordenada,
              []
            );
          }

          coordenadas
            .get(chaveCoordenada)
            .push(String(item.id));
        }
      }

      const telefonesDuplicados = Array.from(
        telefones.entries()
      )
        .filter(([, ids]) => ids.length > 1)
        .map(([telefone, ids]) => ({
          telefone,
          quantidade: ids.length,
          ids
        }))
        .sort(
          (a, b) =>
            b.quantidade - a.quantidade
        );

      const coordenadasDuplicadas = Array.from(
        coordenadas.entries()
      )
        .filter(([, ids]) => ids.length > 1)
        .map(([coordenada, ids]) => ({
          coordenada,
          quantidade: ids.length,
          ids
        }))
        .sort(
          (a, b) =>
            b.quantidade - a.quantidade
        );

      const rankingCidadeId = Object.entries(
        porCidadeId
      )
        .map(([cidade_id, quantidade]) => ({
          cidade_id,
          quantidade
        }))
        .sort(
          (a, b) =>
            b.quantidade - a.quantidade
        );

      const rankingBairros = Object.entries(
        porBairro
      )
        .map(([bairro, quantidade]) => ({
          bairro,
          quantidade
        }))
        .sort(
          (a, b) =>
            b.quantidade - a.quantidade
        )
        .slice(0, 50);

      const distribuicaoMensal =
        Object.entries(porMes)
          .map(([mes, quantidade]) => ({
            mes,
            quantidade
          }))
          .sort((a, b) =>
            b.mes.localeCompare(a.mes)
          );

      return res.json({
        sucesso: true,
        somente_leitura: true,

        consulta: {
          recurso: "contato",
          filtro_ixc:
            "contato.status_viabilidade = N",
          filtro_local:
            "lead = S",
          registros_por_pagina:
            registrosPorPagina,
          limite_paginas:
            limitePaginas,

          total_ixc:
            resultado.total_ixc,

          paginas_previstas:
            resultado.paginas_previstas,

          paginas_processadas:
            resultado.paginas_processadas,

          consulta_completa:
            resultado.consulta_completa,

          duracao_ms:
            Date.now() - inicio
        },

        resumo,

        distribuicao_mensal:
          distribuicaoMensal,

        ranking_cidades_id:
          rankingCidadeId,

        ranking_bairros:
          rankingBairros,

        duplicidades: {
          telefones_duplicados:
            telefonesDuplicados.length,

          coordenadas_duplicadas:
            coordenadasDuplicadas.length,

          amostra_telefones:
            telefonesDuplicados.slice(0, 30),

          amostra_coordenadas:
            coordenadasDuplicadas.slice(0, 30)
        },

        coordenadas_suspeitas:
          coordenadasSuspeitas
      });

    } catch (erro) {
      console.error(
        "[IXC INVIABILIDADE] Erro no diagnóstico:",
        erro.response?.data ||
        erro.message
      );

      return res.status(500).json({
        sucesso: false,
        mensagem:
          "Erro ao executar diagnóstico dos leads inviáveis do IXC.",
        detalhe:
          erro.response?.data ||
          erro.message,
        duracao_ms:
          Date.now() - inicio
      });
    }
  }
);

registrarDebugGet(
  "/api/debug/ixc/contatos-inviaveis",
  async (req, res) => {
    try {
      const limite = Math.min(
        Math.max(Number(req.query.limite || 10), 1),
        50
      );

      const retorno = await buscar(
        "contato",
        "contato.status_viabilidade",
        "N",
        String(limite)
      );

      if (retorno?.type === "error") {
        return res.status(400).json({
          sucesso: false,
          recurso: "contato",
          mensagem:
            retorno.message ||
            "O recurso contato não está disponível."
        });
      }

      const registros = Array.isArray(retorno?.registros)
        ? retorno.registros
        : [];

      return res.json({
        sucesso: true,
        somente_leitura: true,
        recurso: "contato",
        filtro: {
          campo: "contato.status_viabilidade",
          valor: "N"
        },
        total_ixc: Number(retorno?.total || 0),
        total_retornado: registros.length,
        campos_encontrados:
          registros.length > 0
            ? Object.keys(registros[0]).sort()
            : [],
        registros
      });

    } catch (erro) {
      console.error(
        "[IXC CONTATO] Erro ao consultar contatos inviáveis:",
        erro.response?.data || erro.message
      );

      return res.status(500).json({ 
        sucesso: false,
        mensagem:
          "Erro ao consultar o recurso contato no IXC.",
        status_http:
          erro.response?.status || null,
        detalhe:
          erro.response?.data ||
          erro.message
      });
    }
  }
);

registrarDebugGet(
  "/api/debug/ixc/leads-inviaveis-reais",
  async (req, res) => {
    try {
      const limite = Math.min(
        Math.max(Number(req.query.limite || 100), 1),
        500
      );

      const retorno = await buscar(
        "contato",
        "contato.status_viabilidade",
        "N",
        String(limite)
      );

      if (retorno?.type === "error") {
        return res.status(400).json({
          sucesso: false,
          mensagem:
            retorno.message ||
            "Não foi possível consultar os contatos inviáveis."
        });
      }

      const registrosRecebidos = Array.isArray(
        retorno?.registros
      )
        ? retorno.registros
        : [];

      const leadsReais = registrosRecebidos.filter(item =>
        String(item.lead || "")
          .trim()
          .toUpperCase() === "S"
      );

      const resumo = leadsReais.reduce(
        (acc, item) => {
          if (
            String(item.ativo || "")
              .trim()
              .toUpperCase() === "S"
          ) {
            acc.ativos += 1;
          } else {
            acc.inativos += 1;
          }

          const latitude = Number(item.latitude);
          const longitude = Number(item.longitude);

          if (
            Number.isFinite(latitude) &&
            Number.isFinite(longitude) &&
            latitude !== 0 &&
            longitude !== 0
          ) {
            acc.com_coordenadas += 1;
          } else {
            acc.sem_coordenadas += 1;
          }

          return acc;
        },
        {
          ativos: 0,
          inativos: 0,
          com_coordenadas: 0,
          sem_coordenadas: 0
        }
      );

      return res.json({
        sucesso: true,
        somente_leitura: true,

        filtro_ixc: {
          campo: "contato.status_viabilidade",
          valor: "N"
        },

        filtro_local: {
          campo: "lead",
          valor: "S"
        },

        total_ixc_inviaveis:
          Number(retorno?.total || 0),

        total_recebido_na_amostra:
          registrosRecebidos.length,

        total_leads_reais_na_amostra:
          leadsReais.length,

        resumo_amostra: resumo,

        registros: leadsReais.map(item => ({
          id: item.id,
          nome: item.nome,
          ativo: item.ativo,
          lead: item.lead,
          status_viabilidade:
            item.status_viabilidade,
          id_cliente: item.id_cliente,
          data_cadastro: item.data_cadastro,
          endereco: item.endereco,
          numero: item.numero,
          cidade_id: item.cidade,
          bairro: item.bairro,
          latitude: item.latitude,
          longitude: item.longitude,
          distancia_caixa_mais_proxima:
            item.distancia_caixa_mais_proxima,
          id_caixa_ftth: item.id_caixa_ftth,
          observacao: item.obs
        }))
      });

    } catch (erro) {
      console.error(
        "[IXC LEADS INVIÁVEIS] Erro:",
        erro.response?.data || erro.message
      );

      return res.status(500).json({
        sucesso: false,
        mensagem:
          "Erro ao consultar leads inviáveis no IXC.",
        detalhe:
          erro.response?.data ||
          erro.message
      });
    }
  }
);

registrarDebugGet(
  "/api/debug/ixc/descobrir-recurso-leads",
  async (req, res) => {
    const idConhecido = String(
      req.query.id || "13221"
    ).trim();

    /*
     * Estes nomes são candidatos de diagnóstico.
     * A rota não grava nem altera nada no IXC.
     */
    const recursosCandidatos = [
      "crm_leads",
      "crm_contato",
      "crm_contatos",
      "crm_sondagem",
      "crm_sondagens",
      "crm_prospect",
      "crm_prospects"
    ];

    const resultados = [];

    for (const recurso of recursosCandidatos) {
      const tentativasQtype = [
        `${recurso}.id`,
        "id"
      ];

      let resultadoRecurso = null;

      for (const qtype of tentativasQtype) {
        try {
          const params = {
            qtype,
            query: idConhecido,
            oper: "=",
            page: "1",
            rp: "1",
            sortname: "id",
            sortorder: "desc"
          };

          const response = await api.post(
            `/${recurso}`,
            params
          );

          const dados = response.data || {};
          const registros = Array.isArray(dados.registros)
            ? dados.registros
            : [];

          resultadoRecurso = {
            recurso,
            qtype,
            disponivel:
              dados.type !== "error",
            tipo_retorno:
              dados.type || null,
            mensagem:
              dados.message || null,
            total:
              Number(dados.total || registros.length || 0),
            registros_retornados:
              registros.length,
            campos:
              registros[0]
                ? Object.keys(registros[0]).sort()
                : [],
            primeiro_registro:
              registros[0] || null
          };

          /*
           * Encontramos um recurso que respondeu
           * sem rejeitar o endpoint.
           */
          if (dados.type !== "error") {
            break;
          }

        } catch (erro) {
          resultadoRecurso = {
            recurso,
            qtype,
            disponivel: false,
            status_http:
              erro.response?.status || null,
            mensagem:
              erro.response?.data?.message ||
              erro.response?.data ||
              erro.message
          };
        }
      }

      resultados.push(resultadoRecurso);
    }

    return res.json({
      sucesso: true,
      somente_leitura: true,
      id_testado: idConhecido,
      resultados
    });
  }
);

async function buscarContrato(idContrato) {
  if (!idContrato || idContrato === "0") return null;

  const retorno = await buscar(
    "cliente_contrato",
    "cliente_contrato.id",
    idContrato,
    "1"
  );

  return retorno.registros?.[0] || null;
}

async function buscarCliente(idCliente) {
  if (!idCliente || idCliente === "0") return null;

  const retorno = await buscar(
    "cliente",
    "cliente.id",
    idCliente,
    "1"
  );

  return retorno.registros?.[0] || null;
}

async function buscarClienteCache(idCliente) {
  if (!idCliente || idCliente === "0") return null;

  const chave = String(idCliente);
  const cache = obterCache("clientes", chave);

  if (cache) return cache;

  const cliente = await buscarCliente(idCliente);

  salvarCache("clientes", chave, cliente);

  return cliente;
}

async function buscarContratoCache(idContrato) {
  if (!idContrato || idContrato === "0") return null;

  const chave = String(idContrato);
  const cache = obterCache("contratos", chave);

  if (cache) return cache;

  const contrato = await buscarContrato(idContrato);

  salvarCache("contratos", chave, contrato);

  return contrato;
}

async function localizarOSOperacionalCriada({
  contratoId,
  clienteId,
  osPagamentoId,
  assuntos = ["137", "247", "591", "599"],
  tentativas = 6,
  intervaloMs = 1000
}) {
  const contrato = String(contratoId || "");
  const cliente = String(clienteId || "");
  const osPagamento = String(osPagamentoId || "");

  if (!contrato) {
    throw new Error(
      "Contrato não informado para localizar a O.S. operacional."
    );
  }

  const assuntosPermitidos = assuntos.map(item =>
    String(item)
  );

  for (
    let tentativa = 1;
    tentativa <= tentativas;
    tentativa += 1
  ) {
    const retorno = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.id_contrato_kit",
      contrato,
      "100"
    );

    const ordens = Array.isArray(retorno?.registros)
      ? retorno.registros
      : [];

    console.log(
      "[TESTE VELOCIDADE] Ordens retornadas pelo IXC:",
      ordens.map(item => ({
        id: item.id,
        assunto: item.id_assunto,
        status: item.status,
        contrato:
          item.id_contrato_kit ||
          item.id_contrato,
        cliente: item.id_cliente,
        os_anterior: item.id_oss_chamado,
        tarefa: item.id_wfl_tarefa,
        parametro: item.id_wfl_param_os,
        abertura: item.data_abertura
      }))
    );

    const candidatas = ordens
      .filter(item => {
        const mesmoContrato =
          String(
            item.id_contrato_kit ||
            item.id_contrato ||
            ""
          ) === contrato;

        const mesmoCliente =
          !cliente ||
          String(item.id_cliente || "") === cliente;

        const assuntoOperacional =
          assuntosPermitidos.includes(
            String(item.id_assunto || "")
          );

        return (
          mesmoContrato &&
          mesmoCliente &&
          assuntoOperacional
        );
      })
      .sort(
        (a, b) =>
          Number(b.id || 0) -
          Number(a.id || 0)
      );

    const encontrada =
      candidatas[0] || null;

    console.log(
      "[TESTE VELOCIDADE] Busca da O.S. operacional:",
      {
        tentativa,
        contrato_id: contrato,
        cliente_id: cliente || null,
        os_pagamento_id: osPagamento || null,
        assuntos_permitidos:
          assuntosPermitidos,
        total_ordens_contrato:
          ordens.length,
        candidatas_operacionais:
          candidatas.map(item => ({
            id: item.id,
            status: item.status,
            assunto_id: item.id_assunto,
            tarefa:
              item.id_wfl_tarefa || null,
            parametro:
              item.id_wfl_param_os || null,
            data_abertura:
              item.data_abertura || null
          })),
        encontrada: encontrada
          ? {
              id: encontrada.id,
              status: encontrada.status,
              assunto_id:
                encontrada.id_assunto,
              tarefa:
                encontrada.id_wfl_tarefa ||
                null,
              parametro:
                encontrada.id_wfl_param_os ||
                null,
              data_abertura:
                encontrada.data_abertura ||
                null
            }
          : null
      }
    );

    if (encontrada) {
      return encontrada;
    }

    if (tentativa < tentativas) {
      await aguardarIXC(intervaloMs);
    }
  }

  return null;
}

async function criarOSAnexoTesteVelocidade({
  osOperacional
}) {
  if (!osOperacional?.id) {
    throw new Error(
      "A O.S. operacional é obrigatória para criar a O.S. 679."
    );
  }

  const contratoId = String(
    osOperacional.id_contrato_kit ||
    osOperacional.id_contrato ||
    ""
  );

  const clienteId = String(
    osOperacional.id_cliente ||
    ""
  );

  if (!contratoId || contratoId === "0") {
    throw new Error(
      "A O.S. operacional não possui contrato válido."
    );
  }

  if (!clienteId || clienteId === "0") {
    throw new Error(
      "A O.S. operacional não possui cliente válido."
    );
  }

  /*
   * Proteção contra duplicidade.
   * Se a rota for repetida, não cria outra O.S. 679.
   */
  const retornoOrdensContrato = await buscar(
    "su_oss_chamado",
    "su_oss_chamado.id_contrato_kit",
    contratoId,
    "100"
  );

  const ordensContrato = Array.isArray(
    retornoOrdensContrato?.registros
  )
    ? retornoOrdensContrato.registros
    : [];

    const referenciaEsperada =
  `REFERENTE À O.S. ${osOperacional.id}`;

  let osTeste = ordensContrato
      .filter(item =>
        String(item.id_assunto || "") === "679" &&
        String(item.id_cliente || "") === clienteId &&
        String(item.mensagem || "")
          .toUpperCase()
          .includes(
            referenciaEsperada.toUpperCase()
          )
      )
    .sort(
      (a, b) =>
        Number(b.id || 0) -
        Number(a.id || 0)
    )[0] || null;

  let criadaAgora = false;

  if (!osTeste) {
      const payloadCriacao = {

          id_cliente: clienteId,

          id_assunto: "679",

          tipo: "C",

          setor: String(
              osOperacional.setor ||
              "22"
          ),

          id_filial: String(
              osOperacional.id_filial ||
              "1"
          ),

          id_tecnico: "0",

          status: "A",

          prioridade: String(
              osOperacional.prioridade ||
              "N"
          ),

          melhor_horario_agenda: String(
              osOperacional.melhor_horario_agenda ||
              "Q"
          ),

          gera_comissao: "S",

          origem_endereco: "M",

          mensagem:
              `ANEXAR TESTE DE VELOCIDADE REFERENTE À O.S. ${osOperacional.id}.`
      };

    console.log(
      "[TESTE VELOCIDADE] Criando O.S. 679:",
      {
        os_operacional_id:
          osOperacional.id,
        contrato_id:
          contratoId,
        cliente_id:
          clienteId,
        payload:
          payloadCriacao
      }
    );


    const responseCriacao = await api.post(
      "/su_oss_chamado",
      payloadCriacao,
      {
        headers: {
          ixcsoft: "inserir"
        }
      }
    );

    const retornoCriacao =
      responseCriacao.data || {};

    if (
      String(retornoCriacao.type || "")
        .toLowerCase() !== "success"
    ) {
      throw new Error(
        retornoCriacao.message ||
        "O IXC não confirmou a criação da O.S. 679."
      );
    }

    const idCriado = String(
      retornoCriacao.id ||
      ""
    );

    if (!idCriado || idCriado === "0") {
      throw new Error(
        "O IXC confirmou a criação, mas não retornou o ID da O.S. 679."
      );
    }

    await aguardarIXC(300);

    const retornoOSCriada = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.id",
      idCriado,
      "1"
    );

    osTeste =
      retornoOSCriada.registros?.[0] ||
      null;

    if (!osTeste) {
      throw new Error(
        `A O.S. 679 ${idCriado} foi criada, mas não foi localizada para vinculação.`
      );
    }

    criadaAgora = true;
  }

  /*
   * Localiza o login pelo contrato.
   * A O.S. operacional pode vir com id_login = 0.
   */
  let loginId = String(
    osOperacional.id_login ||
    ""
  );

  if (!loginId || loginId === "0") {
    const retornoLogins = await buscar(
      "radusuarios",
      "radusuarios.id_contrato",
      contratoId,
      "20"
    );

    const loginsContrato = Array.isArray(
      retornoLogins?.registros
    )
      ? retornoLogins.registros
      : [];

    const loginContrato =
      loginsContrato.find(item =>
        String(item.id_cliente || "") ===
          clienteId &&
        String(item.ativo || "")
          .toUpperCase() !== "N"
      ) ||
      loginsContrato.find(item =>
        String(item.id_cliente || "") ===
        clienteId
      ) ||
      loginsContrato[0] ||
      null;

    loginId = String(
      loginContrato?.id ||
      ""
    );
  }

  if (!loginId || loginId === "0") {
    throw new Error(
      `Nenhum login foi encontrado para o contrato ${contratoId}.`
    );
  }

  const payloadEdicao = {
    ...osTeste,

    tipo: "C",

    gera_comissao: "S",

    id_login:
      loginId,

    id_contrato_kit:
      contratoId,

    liberado: String(
      osOperacional.liberado ||
      "1"
    ),

    origem_os_aberta: String(
      osOperacional.origem_os_aberta ||
      "P"
    ),

    id_ticket: String(
      osOperacional.id_ticket ||
      "0"
    ),

    origem_endereco:
      "L",

    origem_endereco_estrutura: String(
      osOperacional.origem_endereco_estrutura ||
      "E"
    ),

    latitude: String(
      osOperacional.latitude ||
      ""
    ),

    longitude: String(
      osOperacional.longitude ||
      ""
    ),

    endereco: String(
      osOperacional.endereco ||
      ""
    ),

    bairro: String(
      osOperacional.bairro ||
      ""
    ),

    id_cidade: String(
      osOperacional.id_cidade ||
      "0"
    ),

    complemento: String(
      osOperacional.complemento ||
      ""
    ),

    referencia: String(
      osOperacional.referencia ||
      ""
    ),

    id_condominio: String(
      osOperacional.id_condominio ||
      "0"
    ),

    bloco: String(
      osOperacional.bloco ||
      ""
    ),

    apartamento: String(
      osOperacional.apartamento ||
      ""
    )
  };

  console.log(
    "[TESTE VELOCIDADE] Vinculando O.S. 679:",
    {
      os_operacional_id:
        osOperacional.id,
      os_teste_id:
        osTeste.id,
      contrato_id:
        contratoId,
      cliente_id:
        clienteId,
      login_id:
        loginId,
      criada_agora:
        criadaAgora
    }
  );

  const responseEdicao = await api.put(
    `/su_oss_chamado/${osTeste.id}`,
    payloadEdicao,
    {
      headers: {
        ixcsoft: "editar"
      }
    }
  );

  const retornoEdicao =
    responseEdicao.data || {};

  if (
    String(retornoEdicao.type || "")
      .toLowerCase() !== "success"
  ) {
    throw new Error(
      retornoEdicao.message ||
      "O IXC não confirmou a vinculação da O.S. 679."
    );
  }

  await aguardarIXC(300);

  const retornoValidacao = await buscar(
    "su_oss_chamado",
    "su_oss_chamado.id",
    String(osTeste.id),
    "1"
  );

  const osValidada =
    retornoValidacao.registros?.[0] ||
    null;

  if (!osValidada) {
    throw new Error(
      "A O.S. 679 foi atualizada, mas não pôde ser validada."
    );
  }

  const vinculacaoCorreta =
    String(osValidada.id_cliente || "") ===
      clienteId &&
    String(osValidada.id_contrato_kit || "") ===
      contratoId &&
    String(osValidada.id_login || "") ===
      loginId &&
    String(osValidada.liberado || "") ===
      "1" &&
      String(osValidada.tipo || "") ===
        "C" &&
      String(osValidada.gera_comissao || "") ===
        "S";

  if (!vinculacaoCorreta) {
    throw new Error(
      "A O.S. 679 foi criada, mas os vínculos não foram confirmados pelo IXC."
    );
  }

  console.log(
    "[TESTE VELOCIDADE] O.S. 679 pronta:",
    {
      os_operacional_id:
        osOperacional.id,
      os_teste_id:
        osValidada.id,
      cliente_id:
        osValidada.id_cliente,
      contrato_id:
        osValidada.id_contrato_kit,
      login_id:
        osValidada.id_login,
      liberado:
        osValidada.liberado,
        tipo:
          osValidada.tipo,
        gera_comissao:
          osValidada.gera_comissao,
      origem_endereco:
        osValidada.origem_endereco,
      criada_agora:
        criadaAgora
    }
  );

    return {
      sucesso: true,

      criada_agora:
        criadaAgora,

      os_operacional_id:
        String(osOperacional.id),

      os_teste_velocidade_id:
        String(osValidada.id),

      cliente_id:
        String(osValidada.id_cliente),

      contrato_id:
        String(osValidada.id_contrato_kit),

      login_id:
        String(osValidada.id_login),

      liberado:
        String(osValidada.liberado),

      tipo:
        String(osValidada.tipo),

      gera_comissao:
        String(osValidada.gera_comissao),

      origem_endereco:
        String(osValidada.origem_endereco)
    };
}

function montarPayloadOSTesteVelocidade({
  osOperacional
}) {
  if (!osOperacional?.id) {
    throw new Error(
      "A O.S. operacional é obrigatória para criar a O.S. de teste de velocidade."
    );
  }

  const contratoId = String(
    osOperacional.id_contrato_kit ||
    osOperacional.id_contrato ||
    ""
  );

  const clienteId = String(
    osOperacional.id_cliente ||
    ""
  );

  const loginId = String(
    osOperacional.id_login ||
    ""
  );

  if (!contratoId) {
    throw new Error(
      "A O.S. operacional não possui contrato."
    );
  }

  if (!clienteId) {
    throw new Error(
      "A O.S. operacional não possui cliente."
    );
  }

  if (!loginId) {
    throw new Error(
      "A O.S. operacional não possui login vinculado."
    );
  }

  return {
    id_cliente: clienteId,
    id_contrato_kit: contratoId,
    id_login: loginId,

    id_assunto: "679",
    setor: String(
      osOperacional.setor ||
      "22"
    ),

    id_filial: String(
      osOperacional.id_filial ||
      "1"
    ),

    id_tecnico: "0",

    status: "A",
    prioridade: String(
      osOperacional.prioridade ||
      "N"
    ),

    melhor_horario_agenda: String(
      osOperacional.melhor_horario_agenda ||
      "Q"
    ),

    origem_endereco: String(
      osOperacional.origem_endereco ||
      "CC"
    ),

    origem_endereco_estrutura: String(
      osOperacional.origem_endereco_estrutura ||
      ""
    ),

    latitude: String(
      osOperacional.latitude ||
      ""
    ),

    longitude: String(
      osOperacional.longitude ||
      ""
    ),

    endereco: String(
      osOperacional.endereco ||
      ""
    ),

    bairro: String(
      osOperacional.bairro ||
      ""
    ),

    id_cidade: String(
      osOperacional.id_cidade ||
      ""
    ),

    complemento: String(
      osOperacional.complemento ||
      ""
    ),

    referencia: String(
      osOperacional.referencia ||
      ""
    ),

    id_condominio: String(
      osOperacional.id_condominio ||
      "0"
    ),

    bloco: String(
      osOperacional.bloco ||
      ""
    ),

    apartamento: String(
      osOperacional.apartamento ||
      ""
    ),

    mensagem:
      `ANEXAR TESTE DE VELOCIDADE REFERENTE À O.S. ${osOperacional.id}.`
  };
}

registrarDebugPost(
  "/api/debug/os/:id/criar-teste-velocidade",
  async (req, res) => {
    try {
      const idOSOperacional =
        String(req.params.id || "").trim();

      if (!idOSOperacional) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "Informe a O.S. operacional."
        });
      }

      const retornoOS = await buscar(
        "su_oss_chamado",
        "su_oss_chamado.id",
        idOSOperacional,
        "1"
      );

      const osOperacional =
        retornoOS.registros?.[0];

      if (!osOperacional) {
        return res.status(404).json({
          erro: true,
          mensagem:
            "O.S. operacional não encontrada."
        });
      }

      const assuntosOperacionais = [
        "137",
        "247",
        "591",
        "599"
      ];

      if (
        !assuntosOperacionais.includes(
          String(
            osOperacional.id_assunto ||
            ""
          )
        )
      ) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "A O.S. informada não é uma O.S. operacional reconhecida.",
          assunto_id:
            osOperacional.id_assunto ||
            null
        });
      }

      const contratoId = String(
        osOperacional.id_contrato_kit ||
        ""
      );

      /*
       * Proteção contra duplicidade:
       * verifica se o contrato já possui
       * uma O.S. de assunto 679.
       */
      const retornoOrdensContrato =
        await buscar(
          "su_oss_chamado",
          "su_oss_chamado.id_contrato_kit",
          contratoId,
          "100"
        );

      const ordensContrato =
        Array.isArray(
          retornoOrdensContrato?.registros
        )
          ? retornoOrdensContrato.registros
          : [];

      const osTesteExistente =
        ordensContrato
          .filter(item =>
            String(item.id_assunto || "") ===
              "679" &&
            String(item.id_cliente || "") ===
              String(
                osOperacional.id_cliente ||
                ""
              )
          )
          .sort(
            (a, b) =>
              Number(b.id || 0) -
              Number(a.id || 0)
          )[0] || null;

      if (osTesteExistente) {
        return res.status(409).json({
          erro: true,
          duplicidade: true,
          mensagem:
            "Este contrato já possui uma O.S. de teste de velocidade.",
          os_existente: {
            id: osTesteExistente.id,
            status:
              osTesteExistente.status ||
              null,
            assunto_id:
              osTesteExistente.id_assunto,
            contrato_id:
              osTesteExistente
                .id_contrato_kit ||
              null,
            cliente_id:
              osTesteExistente.id_cliente ||
              null
          }
        });
      }

      const payload =
        montarPayloadOSTesteVelocidade({
          osOperacional
        });

      console.log(
        "[TESTE VELOCIDADE] Payload de criação da O.S. 679:",
        {
          os_operacional_id:
            osOperacional.id,
          contrato_id:
            contratoId,
          cliente_id:
            osOperacional.id_cliente,
          payload
        }
      );

      const response = await api.post(
        "/su_oss_chamado",
        payload,
        {
          headers: {
            ixcsoft: "inserir"
          }
        }
      );

      const retornoIXC =
        response.data || {};

      console.log(
        "[TESTE VELOCIDADE] Resposta da criação da O.S. 679:",
        retornoIXC
      );

      if (
        String(retornoIXC.type || "")
          .toLowerCase() !== "success"
      ) {
        return res.status(400).json({
          erro: true,
          mensagem:
            retornoIXC.message ||
            "O IXC não confirmou a criação da O.S.",
          retorno_ixc:
            retornoIXC,
          payload_enviado:
            payload
        });
      }

      return res.json({
        sucesso: true,
        mensagem:
          "O.S. de teste de velocidade criada pelo IXC.",
        os_operacional_id:
          osOperacional.id,
        os_teste_velocidade_id:
          retornoIXC.id || null,
        retorno_ixc:
          retornoIXC,
        payload_enviado:
          payload
      });

    } catch (erro) {
      console.error(
        "[TESTE VELOCIDADE] Erro ao criar O.S. 679:",
        {
          mensagem:
            erro?.message || null,
          status:
            erro?.response?.status || null,
          retorno_ixc:
            erro?.response?.data || null
        }
      );

      return res.status(500).json({
        erro: true,
        mensagem:
          erro?.response?.data?.message ||
          erro?.message ||
          "Erro ao criar a O.S. de teste de velocidade.",
        status_ixc:
          erro?.response?.status || null,
        retorno_ixc:
          erro?.response?.data || null
      });
    }
  }
);

registrarDebugPost(
  "/api/debug/os/:idOperacional/vincular-teste-velocidade/:idTeste",
  async (req, res) => {
    try {
      const idOperacional =
        String(req.params.idOperacional || "").trim();

      const idTeste =
        String(req.params.idTeste || "").trim();

      const [
        retornoOperacional,
        retornoTeste
      ] = await Promise.all([
        buscar(
          "su_oss_chamado",
          "su_oss_chamado.id",
          idOperacional,
          "1"
        ),

        buscar(
          "su_oss_chamado",
          "su_oss_chamado.id",
          idTeste,
          "1"
        )
      ]);

      const osOperacional =
        retornoOperacional.registros?.[0];

      const osTesteAtual =
        retornoTeste.registros?.[0];

      if (!osOperacional) {
        return res.status(404).json({
          erro: true,
          mensagem:
            "O.S. operacional não encontrada."
        });
      }

      if (!osTesteAtual) {
        return res.status(404).json({
          erro: true,
          mensagem:
            "O.S. de teste de velocidade não encontrada."
        });
      }

      if (
        String(osTesteAtual.id_assunto || "") !==
        "679"
      ) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "A O.S. de destino não possui o assunto 679."
        });
      }

      if (
        String(osOperacional.id_cliente || "") !==
        String(osTesteAtual.id_cliente || "")
      ) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "As duas O.S. não pertencem ao mesmo cliente."
        });
      }

      const loginId =
        String(osOperacional.id_login || "");

      const contratoId =
        String(
          osOperacional.id_contrato_kit ||
          ""
        );

      if (!loginId || loginId === "0") {
        return res.status(400).json({
          erro: true,
          mensagem:
            "A O.S. operacional não possui login válido."
        });
      }

      if (!contratoId || contratoId === "0") {
        return res.status(400).json({
          erro: true,
          mensagem:
            "A O.S. operacional não possui contrato válido."
        });
      }

      const payload = {
        ...osTesteAtual,

        id_login:
          loginId,

        id_contrato_kit:
          contratoId,

          liberado: String(
            osOperacional.liberado ||
            "1"
          ),

          origem_os_aberta: String(
            osOperacional.origem_os_aberta ||
            "P"
          ),

          id_ticket: String(
            osOperacional.id_ticket ||
            "0"
          ),

        origem_endereco:
          "L",

        origem_endereco_estrutura:
          String(
            osOperacional
              .origem_endereco_estrutura ||
            "E"
          ),

        latitude:
          String(
            osOperacional.latitude ||
            ""
          ),

        longitude:
          String(
            osOperacional.longitude ||
            ""
          ),

        endereco:
          String(
            osOperacional.endereco ||
            ""
          ),

        bairro:
          String(
            osOperacional.bairro ||
            ""
          ),

        id_cidade:
          String(
            osOperacional.id_cidade ||
            "0"
          ),

        complemento:
          String(
            osOperacional.complemento ||
            ""
          ),

        referencia:
          String(
            osOperacional.referencia ||
            ""
          ),

        id_condominio:
          String(
            osOperacional.id_condominio ||
            "0"
          ),

        bloco:
          String(
            osOperacional.bloco ||
            ""
          ),

        apartamento:
          String(
            osOperacional.apartamento ||
            ""
          )
      };

      console.log(
        "[TESTE VELOCIDADE] Atualizando vínculos da O.S. 679:",
        {
          os_operacional_id:
            idOperacional,
          os_teste_id:
            idTeste,
          login_id:
            loginId,
          contrato_id:
            contratoId
        }
      );

      const response = await api.put(
        `/su_oss_chamado/${idTeste}`,
        payload,
        {
          headers: {
            ixcsoft: "editar"
          }
        }
      );

      await aguardarIXC(500);

      const retornoValidacao =
        await buscar(
          "su_oss_chamado",
          "su_oss_chamado.id",
          idTeste,
          "1"
        );

      const osAtualizada =
        retornoValidacao.registros?.[0] ||
        null;

      return res.json({
        sucesso:
          response.data?.type === "success",

        mensagem:
          response.data?.message ||
          "Atualização enviada ao IXC.",

        retorno_ixc:
          response.data,

        validacao: osAtualizada
          ? {
              id:
                osAtualizada.id,
              id_cliente:
                osAtualizada.id_cliente,
              id_login:
                osAtualizada.id_login,
              id_contrato_kit:
                osAtualizada.id_contrato_kit,
              origem_endereco:
                osAtualizada.origem_endereco,
              endereco:
                osAtualizada.endereco,
              latitude:
                osAtualizada.latitude,
              longitude:
                osAtualizada.longitude
            }
          : null
      });

    } catch (erro) {
      console.error(
        "[TESTE VELOCIDADE] Erro ao vincular O.S. 679:",
        {
          mensagem:
            erro?.message || null,
          status:
            erro?.response?.status || null,
          retorno_ixc:
            erro?.response?.data || null
        }
      );

      return res.status(500).json({
        erro: true,
        mensagem:
          erro?.response?.data?.message ||
          erro?.message ||
          "Erro ao vincular a O.S. de teste de velocidade.",
        retorno_ixc:
          erro?.response?.data ||
          null
      });
    }
  }
);

registrarDebugPost(
  "/api/debug/os/:id/payload-teste-velocidade",
  async (req, res) => {
    try {
      const idOSOperacional =
        String(req.params.id || "");

      const retornoOS =
        await buscar(
          "su_oss_chamado",
          "su_oss_chamado.id",
          idOSOperacional,
          "1"
        );

      const osOperacional =
        retornoOS.registros?.[0];

      if (!osOperacional) {
        return res.status(404).json({
          erro: true,
          mensagem:
            "O.S. operacional não encontrada."
        });
      }

      const assuntosOperacionais = [
        "137",
        "247",
        "591",
        "599"
      ];

      if (
        !assuntosOperacionais.includes(
          String(
            osOperacional.id_assunto ||
            ""
          )
        )
      ) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "A O.S. informada não é uma O.S. operacional reconhecida."
        });
      }

      const operadorIXC =
        req.session?.usuario
          ?.colaborador_ixc_id ||
        "677";

      const payload =
        montarPayloadOSTesteVelocidade({
          osOperacional,
          operadorIXC
        });

      return res.json({
        sucesso: true,
        somente_diagnostico: true,
        nenhuma_os_criada: true,

        os_operacional: {
          id:
            osOperacional.id,
          cliente_id:
            osOperacional.id_cliente,
          contrato_id:
            osOperacional.id_contrato_kit ||
            osOperacional.id_contrato ||
            null,
          assunto_id:
            osOperacional.id_assunto,
          setor:
            osOperacional.setor ||
            osOperacional.id_setor ||
            null,
          filial_id:
            osOperacional.id_filial ||
            null
        },

        endpoint_futuro:
          "/su_oss_chamado",

        header_futuro: {
          ixcsoft: "inserir"
        },

        payload
      });

    } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao montar payload da O.S. de teste de velocidade"
      );
    }
  }
);

async function limparAlertaCliente(idCliente) {
  if (!idCliente || String(idCliente) === "0") {
    throw new Error("ID do cliente inválido para limpar alerta.");
  }

  const payload = {
    alerta: ""
  };

  const response = await api.put(
    `/cliente/${idCliente}`,
    payload,
    {
      headers: {
        ixcsoft: "editar"
      }
    }
  );

  return response.data;
}

async function buscarPorDataPaginado(endpoint, campoData, data, rp = "1000", maxPaginas = 10) {
  let registros = [];

  for (let page = 1; page <= maxPaginas; page++) {
    const params = {
      qtype: campoData,
      query: data,
      oper: "=",
      page: String(page),
      rp,
      sortname: "id",
      sortorder: "desc"
    };

    const response = await api.post(`/${endpoint}`, params);
    const lista = response.data?.registros || [];

    registros.push(...lista);

    if (lista.length < Number(rp)) {
      break;
    }
  }

  return registros;
}

function formatarDataHora(dataHora) {
  if (!dataHora || dataHora === "0000-00-00 00:00:00") return "";

  const [data, hora] = dataHora.split(" ");
  const [ano, mes, dia] = data.split("-");

  return `${dia}/${mes}/${ano} ${hora?.slice(0, 5) || ""}`;
}

function converterDataBRParaOrdenacao(dataHoraBR) {
  if (!dataHoraBR) return new Date(0);

  const [data, hora] = dataHoraBR.split(" ");
  const [dia, mes, ano] = data.split("/");

  return new Date(`${ano}-${mes}-${dia}T${hora || "00:00"}`);
}

function classificarOS(os) {
  if (os.status === "A" && os.id_tecnico === "0") {
    return "O.S. DE ATIVAÇÃO ABERTA";
  }

  if (os.status === "A") {
    return "O.S. ABERTA";
  }

  if (
  os.status === "AG" &&
  os.id_tecnico === "0" &&
  os.data_reagendar &&
  os.data_reagendar !== "0000-00-00 00:00:00"
  ) {

  return "AGUARDANDO REAGENDAMENTO";
}

  if (os.status === "AG") {
    return "AGENDADA";
  }

    if (os.status === "EX") {
      return "EXECUÇÃO";
    }

    if (os.status === "RAG") {
      return "AGUARDANDO REAGENDAMENTO";
    }

    if (os.status === "R") {
      return "REAGENDADA";
    }

  if (os.status === "F") {
    return "FINALIZADA";
  }

  if (os.status === "DS") {
  return "DESLOCAMENTO";
}

  return `STATUS ${os.status}`;
}

  function classificarGrade(dataAgenda) {
    if (!dataAgenda || dataAgenda === "0000-00-00 00:00:00") {
      return "SEM DATA DE AGENDA";
    }

    const dataOS = new Date(dataAgenda.replace(" ", "T"));

    const hoje = new Date();
    hoje.setHours(0, 0, 0, 0);

    const amanha = new Date(hoje);
    amanha.setDate(hoje.getDate() + 1);

    const limiteGradeDiaSeguinte = new Date(hoje);

    // 0 = domingo, 1 = segunda, ..., 6 = sábado
    if (hoje.getDay() === 6) {
      // Se hoje for sábado, inclui domingo e segunda.
      limiteGradeDiaSeguinte.setDate(hoje.getDate() + 3);
    } else {
      // Nos demais dias, inclui apenas o dia seguinte.
      limiteGradeDiaSeguinte.setDate(hoje.getDate() + 2);
    }

    if (dataOS >= hoje && dataOS < amanha) {
      return "GRADE DE HOJE";
    }

    if (dataOS >= amanha && dataOS < limiteGradeDiaSeguinte) {
      return "GRADE DO DIA SEGUINTE";
    }

    if (dataOS >= limiteGradeDiaSeguinte) {
      return "AGENDA FUTURA";
    }

    return "AGENDA ANTERIOR";
  }

function gerarResumo(lista, campo) {
  return Object.entries(
    lista.reduce((acc, item) => {
      acc[item[campo]] = (acc[item[campo]] || 0) + 1;
      return acc;
    }, {})
  ).map(([nome, quantidade]) => ({
    nome,
    quantidade
  }));
}

async function listarOrdensMonitoradas() {

      const timerListar = `listarOrdensMonitoradas-${Date.now()}`;
      console.time(timerListar);



  const resultado = [];

        const retornosOS = await Promise.all(
          Object.keys(assuntosMonitorados).map(async (idAssunto) => {
            const retornoOS = await buscar(
              "su_oss_chamado",
              "su_oss_chamado.id_assunto",
              idAssunto,
              "1000"
            );

            return {
              idAssunto,
              ordens: retornoOS.registros || []
            };
          })
        );

for (const grupo of retornosOS) {
  const idAssunto = grupo.idAssunto;
  let ordens = grupo.ordens;

    const idsIgnorados = ["761", "325"];
    const osIgnoradas = ["2048801"];

    ordens = ordens.filter(os =>
      os.id_cliente !== "0" &&
      os.id_cliente !== 0 &&
      !osIgnoradas.includes(String(os.id))
    );

    function ehHoje(dataHora) {
  if (!dataHora || dataHora === "0000-00-00 00:00:00") return false;

  const data = new Date(dataHora.replace(" ", "T"));

  const hoje = new Date();
  hoje.setHours(0, 0, 0, 0);

  const amanha = new Date(hoje);
  amanha.setDate(hoje.getDate() + 1);

  return data >= hoje && data < amanha;
}

const ordensValidas = ordens.filter((os) => {
  const situacao = classificarOS(os);

  const grade =
    os.status === "RAG"
      ? "AGUARDANDO NOVA DATA"
      : classificarGrade(os.data_agenda);

  const osAbertaParaAgendar =
    situacao === "O.S. DE ATIVAÇÃO ABERTA";

  const osAgendadaAtualOuFutura =
    ["GRADE DE HOJE", "GRADE DO DIA SEGUINTE", "AGENDA FUTURA"].includes(grade);

  const osEmExecucao =
    situacao === "EXECUÇÃO";

  const osAguardandoReagendamento =
    situacao === "AGUARDANDO REAGENDAMENTO";

  const osReagendadaAtualOuFutura =
    situacao === "REAGENDADA" &&
    ["GRADE DE HOJE", "GRADE DO DIA SEGUINTE", "AGENDA FUTURA"].includes(grade);

    const osTerceirizadoMes =
      os.id_tecnico === "16" &&
      os.data_agenda &&
      os.data_agenda !== "0000-00-00 00:00:00" &&
      new Date(os.data_agenda.replace(" ", "T")).getMonth() === new Date().getMonth() &&
      new Date(os.data_agenda.replace(" ", "T")).getFullYear() === new Date().getFullYear();

  const osFinalizadaHoje =
    situacao === "FINALIZADA" &&
    ehHoje(os.data_fechamento || os.data_final || os.ultima_atualizacao);

  return (
    osAbertaParaAgendar ||
    osAgendadaAtualOuFutura ||
    osEmExecucao ||
    osAguardandoReagendamento ||
    osReagendadaAtualOuFutura ||
    osTerceirizadoMes ||
    osFinalizadaHoje
  );
});

    for (const os of ordensValidas) {
        const [contrato, cliente] = await Promise.all([
          buscarContratoCache(os.id_contrato_kit),
          buscarClienteCache(os.id_cliente)
        ]);

      const idVendedor =
        contrato?.id_vendedor ||
        cliente?.id_vendedor ||
        "";

        if (
        idsIgnorados.includes(idVendedor) ||
        idsIgnorados.includes(os.id_tecnico)
      ) {
        continue;
      }

      resultado.push({
        tipo_os: assuntosMonitorados[os.id_assunto] || `Assunto ID ${os.id_assunto}`,
        assunto_id: os.id_assunto,
        situacao_os: classificarOS(os),
        grade:
          os.id_tecnico === "16"
            ? "TERCEIRIZADOS"
            : os.status === "RAG"
              ? "AGUARDANDO NOVA DATA"
      : classificarGrade(os.data_agenda),
        os: os.id,
        cliente: cliente?.razao || `Cliente ID ${os.id_cliente}`,
        vendedor_id: idVendedor,
        vendedor: vendedores[idVendedor] || `Vendedor ID ${idVendedor}`,
        tecnico_id: os.id_tecnico,
          tecnico_id: os.id_tecnico,
          tecnico:
            os.id_tecnico === "0"
              ? classificarOS(os)
              : tecnicos[os.id_tecnico] || `Técnico ID ${os.id_tecnico}`,
          cor_tecnico: coresTecnicos[os.id_tecnico] || "#94a3b8",
        data_agenda: formatarDataHora(os.data_agenda),
        data_agenda_final: formatarDataHora(os.data_agenda_final),
        data_reagendar: formatarDataHora(os.data_reagendar),
        cidade_id: os.id_cidade,
        contrato: os.id_contrato_kit,
        status: os.status
      });
    }
  }


  resultado.sort((a, b) => {
    const dataA = converterDataBRParaOrdenacao(a.data_agenda);
    const dataB = converterDataBRParaOrdenacao(b.data_agenda);
    return dataA - dataB;
  });


  console.timeEnd(timerListar);

  return {
    total: resultado.length,
    ordens: resultado,
    ativacoes: resultado,
    resumo_situacoes: gerarResumo(resultado, "situacao_os"),
    resumo_grades: gerarResumo(resultado, "grade"),
    resumo_vendedores: gerarResumoPorVendedor(resultado),
    resumo_tecnicos: gerarResumo(resultado, "tecnico"),
    resumo_tipos: gerarResumo(resultado, "tipo_os")
  };
}

function gerarResumoPorVendedor(lista) {
  const resumo = {};

  for (const item of lista) {
    if (!resumo[item.vendedor]) {
      resumo[item.vendedor] = {
        vendedor: item.vendedor,
        grade_hoje: 0,
        grade_dia_seguinte: 0,
        instalados_dia: 0,
        reagendados_dia: 0,
        finalizadas_dia: 0
      };
    }

    if (item.situacao_os === "AGENDADA" && item.grade === "GRADE DE HOJE") {
      resumo[item.vendedor].grade_hoje += 1;
    }

    if (item.situacao_os === "AGENDADA" && item.grade === "GRADE DO DIA SEGUINTE") {
      resumo[item.vendedor].grade_dia_seguinte += 1;
    }

    if (item.situacao_os === "EXECUÇÃO") {
      resumo[item.vendedor].instalados_dia += 1;
    }

    if (
      item.situacao_os === "REAGENDADA" ||
      item.situacao_os === "AGUARDANDO REAGENDAMENTO"
    ) {
      resumo[item.vendedor].reagendados_dia += 1;
    }

    if (item.situacao_os === "FINALIZADA") {
      resumo[item.vendedor].finalizadas_dia += 1;
    }
  }

  return Object.values(resumo);
}

let cacheAtivacoes = null;
let cacheAtivacoesCriadoEm = 0;
const TEMPO_CACHE_ATIVACOES = 70 * 1000;


app.get("/api/ativacoes", exigirLogin, async (req, res) => {
  try {
    const agora = Date.now();
    const cacheValido =
      cacheAtivacoes &&
      agora - cacheAtivacoesCriadoEm < TEMPO_CACHE_ATIVACOES;

    let dados;

    if (cacheValido) {
      dados = JSON.parse(JSON.stringify(cacheAtivacoes));
    } else {
      dados = await listarOrdensMonitoradas();
      cacheAtivacoes = JSON.parse(JSON.stringify(dados));
      cacheAtivacoesCriadoEm = agora;
    }

    const usuarioLogado = req.session.usuario;

    dados.ordens = dados.ordens.filter((ordem) =>
      vendedorPermitido(usuarioLogado, ordem.vendedor_id)
    );

    dados.ativacoes = dados.ordens;
    dados.total = dados.ordens.length;
    dados.resumo_situacoes = gerarResumo(dados.ordens, "situacao_os");
    dados.resumo_grades = gerarResumo(dados.ordens, "grade");
    dados.resumo_vendedores = gerarResumoPorVendedor(dados.ordens);
    dados.resumo_tecnicos = gerarResumo(dados.ordens, "tecnico");
    dados.resumo_tipos = gerarResumo(dados.ordens, "tipo_os");

    res.json({
      ...dados,
      cache: cacheValido,
      atualizado_em: new Date(cacheAtivacoesCriadoEm).toLocaleString("pt-BR")
    });

      } catch (erro) {
        return responderErroInterno(
          req,
          res,
          erro,
          "Erro ao consultar ativações"
        );
      }
});

async function atualizarCacheAtivacoes() {
  try {
    console.log("Atualizando cache de ativações...");

    const dados = await listarOrdensMonitoradas();

    cacheAtivacoes = JSON.parse(JSON.stringify(dados));
    cacheAtivacoesCriadoEm = Date.now();

    console.log(
      `Cache de ativações atualizado: ${dados.total} registros às ${new Date().toLocaleString("pt-BR")}`
    );
  } catch (erro) {
    console.error("Erro ao atualizar cache de ativações:", erro.message);
  }
}


app.post("/api/os/:id/mensagem", exigirLogin,  exigirPermissao("operar_os"), async (req, res) => {
  try {
    const { mensagem, idTecnico } = req.body;

    if (!mensagem) {
      return res.status(400).json({
        erro: true,
        mensagem: "Mensagem é obrigatória."
      });
    }

    const payload = {
      id_chamado: req.params.id,
      status: "A",
      id_evento: "11",
      mensagem,
      historico: "",
      id_tecnico: idTecnico || "0",
      id_equipe: "",
      finaliza_processo: "N",
      id_operador: "677",
      tipo_cobranca: "NENHUM"
    };

    const response = await api.post("/su_oss_chamado_mensagem", payload, {
      headers: {
        ixcsoft: "inserir"
      }
    });

    res.json({
      sucesso: true,
      retorno: response.data
    });
    
  } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao adicionar mensagem na O.S."
      );
  }
});

app.post("/api/os/:id/descricao-confirmacao", exigirLogin,   exigirPermissao("operar_os"), async (req, res) => {
  try {
    const idOS = req.params.id;
    const { observacao } = req.body || {};

    if (!observacao || !observacao.trim()) {
      return res.json({
        sucesso: true,
        mensagem: "Nenhuma observação enviada para a descrição."
      });
    }

    const retornoOS = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.id",
      idOS,
      "1"
    );

    const osAtual = retornoOS.registros?.[0];

    if (!osAtual) {
      return res.status(404).json({
        erro: true,
        mensagem: "O.S. não encontrada."
      });
    }

    if (!["137", "247", "599", "591"].includes(String(osAtual.id_assunto))) {
      return res.status(400).json({
        erro: true,
        mensagem: "Esta O.S. não é uma O.S. de ativação reconhecida."
      });
    }

    const separador = "----------------------------------------";
    const descricaoAtual = String(osAtual.mensagem || "").trim();

    const descricaoSemObservacaoAntiga = descricaoAtual
      .replace(
        /^Observação:[\s\S]*?Registrado em:[^\n]*\n-+\n*/i,
        ""
      )
      .trim();

    const blocoObservacao = [
      `Observação: ${observacao.trim()}`,
      `Registrado em: ${new Date().toLocaleString("pt-BR")}`,
      separador
    ].join("\n");

    const novaDescricao = `${blocoObservacao}\n\n${descricaoSemObservacaoAntiga}`.trim();

    const payload = {
      ...osAtual,
      mensagem: novaDescricao
    };

    const response = await api.put(`/su_oss_chamado/${idOS}`, payload, {
      headers: {
        ixcsoft: "editar"
      }
    });

    await registrarLogSistema(req, {
        acao: "ADICIONOU_OBSERVACAO_OS",
        modulo: "Confirmações",
        os_id: String(idOS),
        cliente: osAtual.id_cliente ? `Cliente ID ${osAtual.id_cliente}` : null,
        detalhes: observacao.trim()
      });

    return res.json({
      sucesso: true,
      mensagem: "Descrição da O.S. atualizada com sucesso.",
      retorno: response.data
    });

  } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao atualizar descrição da O.S."
      );
  }
});

app.post("/api/os/:id/reagendar", exigirLogin, exigirPermissao("operar_os"), async (req, res) => {
  try {
    const idOS = req.params.id;
    const { motivo } = req.body;

    if (!motivo || !motivo.trim()) {
      return res.status(400).json({
        erro: true,
        mensagem: "Motivo do reagendamento é obrigatório."
      });
    }

    const retornoOS = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.id",
      idOS,
      "1"
    );

    const osAtual = retornoOS.registros?.[0];

    if (!osAtual) {
      return res.status(404).json({
        erro: true,
        mensagem: "O.S. não encontrada."
      });
    }

    if (osAtual.status === "F") {
      return res.status(400).json({
        erro: true,
        mensagem: "Não é possível reagendar uma O.S. finalizada."
      });
    }

    const reagendamentoPayload = {
      id_chamado: idOS,
      id_resposta: "",
      mensagem: motivo.trim(),
      status: "RAG",
      data: "",
      id_evento: "",
      id_compromisso: "",
      latitude: "",
      longitude: "",
      gps_time: "",
      id_setor: osAtual.setor || "22",
      id_tecnico: "",
      historico: ""
    };

    const reagendamentoResponse = await api.post(
      "/su_oss_chamado_reagendamento",
      reagendamentoPayload,
      {
        headers: {
          ixcsoft: "inserir"
        }
      }
    );

    console.log("Reagendamento IXC:", reagendamentoResponse.data);

          if (reagendamentoResponse.data?.type !== "success") {
            return res.status(400).json({
              erro: true,
              mensagem:
                reagendamentoResponse.data?.message ||
                "Não foi possível registrar o reagendamento.",
              retorno: reagendamentoResponse.data
            });
          }

          const contrato = await buscarContratoCache(osAtual.id_contrato_kit);
          const cliente = await buscarClienteCache(osAtual.id_cliente);

          const idVendedor =
            contrato?.id_vendedor ||
            cliente?.id_vendedor ||
            "";

          const usuario =
            req.session?.usuario?.nome ||
            req.session?.usuario?.usuario ||
            "-";

          await db.query(
            `
            INSERT INTO historico_reagendamentos
              (os_id, cliente, vendedor, tecnico, tecnico_id, contrato, motivo, reagendado_por)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [
              String(idOS),
              cliente?.razao || `Cliente ID ${osAtual.id_cliente}`,
              vendedores[idVendedor] || `Vendedor ID ${idVendedor}`,
              tecnicos[osAtual.id_tecnico] || `Técnico ID ${osAtual.id_tecnico}`,
              osAtual.id_tecnico || "",
              osAtual.id_contrato_kit || "",
              motivo.trim(),
              usuario
            ]
          );

          await db.query(
            "DELETE FROM confirmacoes_os WHERE os_id = ?",
            [String(idOS)]
          );
        
          await db.query(
          "DELETE FROM lista_confirmacao_os WHERE os_id = ?",
          [String(idOS)]
        );

          listaConfirmacaoAtual = listaConfirmacaoAtual.filter(item =>
            String(item.os) !== String(idOS)
          );

          await registrarLogSistema(req, {
            acao: "REAGENDOU_OS",
            modulo: "Comercial Operacional",
            os_id: String(idOS),
            cliente: cliente?.razao || `Cliente ID ${osAtual.id_cliente}`,
            detalhes: `Motivo: ${motivo.trim()}`
          });

          res.json({
            sucesso: true,
            reagendamento: reagendamentoResponse.data,
            historico_salvo: true
          });

  } catch (erro) {
        return responderErroInterno(
          req,
          res,
          erro,
          "Erro ao reagendar O.S."
        );
  }
});

if (process.env.NODE_ENV !== "production") {
app.get("/api/debug-os/:id", exigirLogin, exigirSuperAdmin, async (req, res) => {
  try {
    const retorno = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.id",
      req.params.id,
      "1"
    );

    res.json(retorno.registros?.[0] || null);
  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});


app.get("/api/debug-ranking-contratos", exigirLogin, exigirSuperAdmin, async (req, res) => {
  try {
    const dataInicial = req.query.inicio || "2026-06-20";
    const dataFinal = req.query.fim || "2026-06-20";

    const retorno = await buscar(
      "cliente_contrato",
      "cliente_contrato.data_ativacao",
      dataInicial,
      "1000"
    );

    const contratos = (retorno.registros || []).filter(contrato => {
      const dataAtivacao = contrato.data_ativacao || "";
      return dataAtivacao >= dataInicial && dataAtivacao <= dataFinal;
    });

    res.json({
      total: contratos.length,
      contratos
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      status: erro.response?.status || null,
      mensagem: erro.response?.data || erro.message
    });
  }
});

app.get("/api/debug-plano/:id", exigirLogin, exigirSuperAdmin, async (req, res) => {
  try {
    const id = req.params.id;

    const retorno = await buscar(
      "vd_contratos",
      "id",
      id,
      "1"
    );

    res.json(retorno);

  } catch (erro) {
    res.status(500).json({
      erro: true,
      status: erro.response?.status || null,
      mensagem: erro.response?.data || erro.message
    });
  }
});

}


function numeroIXC(valor) {
  return Number(String(valor || "0").replace(",", "."));
}


function nomeVendedorRanking(id) {
  const idStr = String(id || "0");
  return vendedores[idStr] || `Vendedor não mapeado - ID ${idStr}`;
}


function gerarDatasPeriodo(inicio, fim) {
  const datas = [];
  const atual = new Date(`${inicio}T00:00:00`);
  const limite = new Date(`${fim}T00:00:00`);

  while (atual <= limite) {
    datas.push(atual.toISOString().slice(0, 10));
    atual.setDate(atual.getDate() + 1);
  }

  return datas;
}

// COMEÇO DA API DO RANKING CHURN //

const cacheRankingChurn = {};
const TEMPO_CACHE_CHURN_MS = 5 * 60 * 1000;

function extrairValorPlanoNovoChurn(texto) {
  const conteudo = String(texto || "");

  const matchPlanoNovo = conteudo.match(/PLANO NOVO:[\s\S]*?VALOR:\s*R\$\s*([\d.,]+)/i);

  if (matchPlanoNovo) {
    return numeroIXC(matchPlanoNovo[1]);
  }

  const valores = [...conteudo.matchAll(/VALOR:\s*R\$\s*([\d.,]+)/gi)];

  if (valores.length >= 2) {
    return numeroIXC(valores[1][1]);
  }

  return 0;
}

function classificarRenovacaoChurn(texto) {
  const conteudo = String(texto || "").toUpperCase();

  const valores = [...conteudo.matchAll(/VALOR:\s*R\$\s*([\d.,]+)/gi)]
    .map(item => numeroIXC(item[1]));

  if (valores.length >= 2) {
    const antigo = valores[0];
    const novo = valores[1];

    if (novo > antigo) return "UPGRADE";
    if (novo < antigo) return "DOWNGRADE";
    return "MANTEVE";
  }

  if (conteudo.includes("UPGRADE")) return "UPGRADE";
  if (conteudo.includes("DOWNGRADE")) return "DOWNGRADE";

  return "NAO_IDENTIFICADO";
}

function dataValidaIXC(data) {
  return data && data !== "0000-00-00 00:00:00";
}



// COMEÇO DA API DO RANKING //  

const RC_RANKING_CHURN = {
  "71": "RC - GABRIEL MATOS OLIVEIRA",
  "299": "RC - DARIANE MORAES",
  "68": "RC - AMANDA OLIVEIRA CARDOSO",
  "113": "RC - RHYAN WILLIAMS SOUSA BAÍA"
};



const VENDEDORES_RANKING = [
  "11",   // Sheyla
  "17",   // Luana
  "18",   // Rafaele
  "42",   // Daniella
  "49",   // Alice
  "63",   // Samara
  "151",  // Karina
  "152",  // Amanda Nabate
  "210",  // Vitor Hugo
  "219",  // Rangelle
  "220",  // Ingrid
  "339",  // Rafaela
  "375",  // Wadsom
  "377"   // Amanda Pantoja
];


const cacheRankingReceita = {};
const cachePlanosRanking = {};
const TEMPO_CACHE_RANKING_MS = 5 * 60 * 1000;

const METAS_VENDEDORES = {
  "210": 7500,
  "151": 10000,
  "17": 10650,
  "42": 10000,
  "49": 10000,
  "339": 10000,
  "152": 10000,
  "220": 10000,
  "11": 10650,
  "219": 8000,
  "63": 8000,
  "18": 10200,
  "375": 8000,
  "943": 8000
};

function obterMetaVendedor(idVendedor) {
  return METAS_VENDEDORES[String(idVendedor)] || 0;
}


app.get("/api/ranking-receita", exigirLogin, async (req, res) => {
  try {
    const dataInicial = req.query.inicio;
    const dataFinal = req.query.fim;

    if (!dataInicial || !dataFinal) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe inicio e fim no formato YYYY-MM-DD."
      });
    }

    const usuarioSessao = req.session.usuario || {};
    const perfilUsuario = usuarioSessao.perfil;
    const vendedorUsuarioId = String(usuarioSessao.vendedor_id || "");

    const mesRanking = dataInicial.slice(0, 7);

    const [metasRows] = await db.query(
            `
            SELECT vendedor_id, meta
            FROM metas_vendedores
            WHERE mes = ? AND ativo = 1
            `,
            [mesRanking]
          );

          const metasBanco = {};

          metasRows.forEach(item => {
            metasBanco[String(item.vendedor_id)] = Number(item.meta || 0);
          });

    const desejaRankingGeral = req.query.geral === "1";
    const podeVerRankingGeral = usuarioSessao.permissoes?.includes("ver_ranking_geral");


    const chaveCache = `${perfilUsuario}_${vendedorUsuarioId}_${desejaRankingGeral}_${dataInicial}_${dataFinal}`;

    // const cache = cacheRankingReceita[chaveCache];

    // if (cache && Date.now() - cache.criadoEm < TEMPO_CACHE_RANKING_MS) { // 
      // return res.json({ //
        // ...cache.dados, //
        // cache: true //
     // }); //
   // } //

    const datasPeriodo = gerarDatasPeriodo(dataInicial, dataFinal);
    let contratos = [];

    for (const data of datasPeriodo) {
      const retornoContratos = await buscar(
        "cliente_contrato",
        "cliente_contrato.data_ativacao",
        data,
        "1000"
      );

      contratos.push(...(retornoContratos.registros || []));
    }

    const contratosUnicosMap = new Map();

for (const contrato of contratos) {
  const chaveContrato = String(contrato.id || "");

  if (!chaveContrato) continue;

  if (!contratosUnicosMap.has(chaveContrato)) {
    contratosUnicosMap.set(chaveContrato, contrato);
  }
}

contratos = [...contratosUnicosMap.values()];

    

    async function obterPlano(idPlano) {
      if (!idPlano || idPlano === "0") return null;

      if (cachePlanosRanking[idPlano]) {
        return cachePlanosRanking[idPlano];
      }

      const retornoPlano = await buscar(
        "vd_contratos",
        "id",
        idPlano,
        "1"
      );

      const plano = retornoPlano.registros?.[0] || null;
      cachePlanosRanking[idPlano] = plano;

      return plano;
    }

      const [regrasRows] = await db.query(
      `
      SELECT id_plano_venda, receita_calculada
      FROM regras_receita_ranking
      WHERE mes = ? AND ativo = 1
      `,
      [mesRanking]
    );

    const regrasReceita = {};

    regrasRows.forEach(regra => {
      regrasReceita[String(regra.id_plano_venda)] = Number(regra.receita_calculada || 0);
    });

    const mapa = {};

    for (const contrato of contratos) {
      const idVendedor = contrato.id_vendedor || "0";

      if (!VENDEDORES_RANKING.includes(String(idVendedor))) {
        continue;
      }

      const idPlano = contrato.id_vd_contrato;
      const plano = await obterPlano(idPlano);

      const receitaPadrao = numeroIXC(plano?.valor_contrato);

      const receitaMensal = regrasReceita[String(idPlano)]
        ? regrasReceita[String(idPlano)]
        : receitaPadrao;

      const taxaInstalacao = numeroIXC(contrato.taxa_instalacao);

      if (!mapa[idVendedor]) {
        mapa[idVendedor] = {
          id_vendedor: idVendedor,
          vendedor: nomeVendedorRanking(idVendedor),
          tipo_origem: "vendedor",
          contratos: 0,
          receita_mensal: 0,
          taxa_instalacao: 0,
          ticket_medio: 0,
          itens: []
        };
      }

      mapa[idVendedor].contratos += 1;
      mapa[idVendedor].receita_mensal += receitaMensal;
      mapa[idVendedor].taxa_instalacao += taxaInstalacao;

      mapa[idVendedor].itens.push({
        contrato_id: contrato.id,
        cliente_id: contrato.id_cliente,
        data_ativacao: contrato.data_ativacao,
        plano_id: idPlano,
        plano: plano?.nome || contrato.contrato || "-",
        receita_mensal: receitaMensal,
        receita_padrao: receitaPadrao,
        receita_ajustada: Boolean(regrasReceita[String(idPlano)]),
        taxa_instalacao: taxaInstalacao
      });
    }

    const rankingCompleto = Object.values(mapa)
      .map(item => {
        const meta = metasBanco[String(item.id_vendedor)] || 0;
        const receita = Number(item.receita_mensal.toFixed(2));
        const falta = Math.max(meta - receita, 0);
        const percentual = meta ? (receita / meta) * 100 : 0;

        return {
          ...item,
          receita_mensal: receita,
          taxa_instalacao: Number(item.taxa_instalacao.toFixed(2)),
          ticket_medio: item.contratos
            ? Number((receita / item.contratos).toFixed(2))
            : 0,
          meta: Number(meta.toFixed(2)),
          percentual_meta: Number(percentual.toFixed(2)),
          falta_meta: Number(falta.toFixed(2))
        };
      })
      .sort((a, b) => b.receita_mensal - a.receita_mensal)
      .map((item, index) => ({
        ...item,
        posicao: index + 1
      }));

    let ranking = rankingCompleto;

      if (perfilUsuario === "vendedor") {
        if (!vendedorUsuarioId) {
          return res.status(403).json({
            erro: true,
            mensagem: "Usuário vendedor sem vendedor_id vinculado."
          });
        }

        if (!(desejaRankingGeral && podeVerRankingGeral)) {
          ranking = rankingCompleto.filter(item =>
            String(item.id_vendedor) === vendedorUsuarioId
          );
        }
      }

    const respostaRanking = {
      periodo: {
        inicio: dataInicial,
        fim: dataFinal
      },
      total_contratos_ixc: contratos.length,
      total_contratos_ranking: ranking.reduce(
        (soma, item) => soma + item.contratos,
        0
      ),
      ranking,
      usuario: {
        perfil: perfilUsuario,
        vendedor_id: vendedorUsuarioId || null
      },
      cache: false
    };

    cacheRankingReceita[chaveCache] = {
      criadoEm: Date.now(),
      dados: respostaRanking
    };

    res.json(respostaRanking);

  } catch (erro) {
    res.status(500).json({
      erro: true,
      status: erro.response?.status || null,
      mensagem: erro.response?.data || erro.message
    });
  }
});

const cachePlanosChurn = {};

async function obterPlanoChurn(idPlano) {
  if (!idPlano || idPlano === "0") return null;

  if (cachePlanosChurn[idPlano]) {
    return cachePlanosChurn[idPlano];
  }

  const retornoPlano = await buscar(
    "vd_contratos",
    "id",
    idPlano,
    "1"
  );

  const plano = retornoPlano.registros?.[0] || null;
  cachePlanosChurn[idPlano] = plano;

  return plano;
}

function normalizarTextoPlanoChurn(texto) {
  return String(texto || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toUpperCase()
    .replace(/\s+/g, " ")
    .trim();
}

function extrairPlanosChurn(texto) {
  const conteudo = String(texto || "");

  const antigoMatch = conteudo.match(/PLANO\s+ANTIGO:\s*([^\n\r]+)/i);
  const novoMatch = conteudo.match(/PLANO\s+NOVO:\s*([^\n\r]+)/i);

  return {
    planoAntigoTexto: antigoMatch ? antigoMatch[1].trim() : "",
    planoNovoTexto: novoMatch ? novoMatch[1].trim() : ""
  };
}

async function obterPlanoChurnPorNome(nomePlanoTexto) {
  const nomeNormalizado = normalizarTextoPlanoChurn(nomePlanoTexto);

  if (!nomeNormalizado) return null;

  const retorno = await buscar(
    "vd_contratos",
    "vd_contratos.nome",
    nomePlanoTexto,
    "1"
  );

  const planoDireto = retorno.registros?.[0] || null;

  if (planoDireto) return planoDireto;

  return null;
}

function extrairValorMonetarioChurn(texto) {
  const match = String(texto || "").match(/VALOR:\s*R\$\s*([\d.,]+)/i);

  if (!match) return 0;

  return Number(
    match[1]
      .replace(/\./g, "")
      .replace(",", ".")
  ) || 0;
}

function valorChurnValido(valor) {
  return Number.isFinite(Number(valor)) && Number(valor) > 0;
}

async function classificarRenovacaoChurnPorTexto(texto) {
  const conteudo = String(texto || "");

  const matchPlanoAntigo = conteudo.match(
    /PLANO\s+ANTIGO:[\s\S]*?VALOR:\s*R\$\s*([\d.,]+)/i
  );

  const matchPlanoNovo = conteudo.match(
    /PLANO\s+NOVO:[\s\S]*?VALOR:\s*R\$\s*([\d.,]+)/i
  );

  if (!matchPlanoAntigo || !matchPlanoNovo) {
    return "NAO_IDENTIFICADO";
  }

  const valorAntigo = numeroIXC(matchPlanoAntigo[1]);
  const valorNovo = numeroIXC(matchPlanoNovo[1]);

  if (!valorAntigo || !valorNovo) {
    return "NAO_IDENTIFICADO";
  }

  if (valorNovo > valorAntigo) return "UPGRADE";
  if (valorNovo < valorAntigo) return "DOWNGRADE";

  return "MANTEVE";
}

const cachePlanosChurnPorId = {};
const cachePlanosChurnPorNome = {};

function chavePlanoChurn(nome) {
  return String(nome || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toUpperCase()
    .replace(/\s+/g, " ")
    .trim();
}

async function obterPlanoChurnPorId(idPlano) {
  if (!idPlano || idPlano === "0") return null;

  if (cachePlanosChurnPorId[idPlano]) {
    return cachePlanosChurnPorId[idPlano];
  }

  const retorno = await buscar("vd_contratos", "id", idPlano, "1");
  const plano = retorno.registros?.[0] || null;

  if (plano) {
    cachePlanosChurnPorId[idPlano] = plano;
    cachePlanosChurnPorNome[chavePlanoChurn(plano.nome)] = plano;
  }

  return plano;
}

async function obterPlanoChurnPorNome(nomePlano) {
  const chave = chavePlanoChurn(nomePlano);
  if (!chave) return null;

  if (cachePlanosChurnPorNome[chave]) {
    return cachePlanosChurnPorNome[chave];
  }

  const retorno = await buscar("vd_contratos", "vd_contratos.nome", nomePlano, "1");
  const plano = retorno.registros?.[0] || null;

  if (plano) {
    cachePlanosChurnPorId[plano.id] = plano;
    cachePlanosChurnPorNome[chavePlanoChurn(plano.nome)] = plano;
  }

  return plano;
}



// =========================================================
// RELATÓRIOS COMERCIAIS - BI DE ATIVAÇÕES
// =========================================================

const cacheRelatorioAtivacoes = {};

const consultasRelatorioAtivacoesEmAndamento =
  new Map();

const MAX_CACHE_RELATORIO_ATIVACOES = 20;


const cachePlanosRelatorioAtivacoes = {};
const cacheFiliaisRelatorioAtivacoes = {};

const TEMPO_CACHE_RELATORIO_ATIVACOES_MS =
  5 * 60 * 1000;

const FILIAIS_COMERCIAIS = {
  "1": "VELLON MATRIZ",
  "2": "VELLON CASTANHAL",
  "13": "VELLON BUJARU"
};

  function limparCacheRelatorioAtivacoes() {
  const agora = Date.now();

  for (
    const [chave, item]
    of Object.entries(cacheRelatorioAtivacoes)
  ) {
    if (
      !item ||
      agora - item.criadoEm >
        TEMPO_CACHE_RELATORIO_ATIVACOES_MS
    ) {
      delete cacheRelatorioAtivacoes[chave];
    }
  }

  const chaves =
    Object.keys(cacheRelatorioAtivacoes);

  if (
    chaves.length <=
    MAX_CACHE_RELATORIO_ATIVACOES
  ) {
    return;
  }

  chaves
    .sort(
      (a, b) =>
        cacheRelatorioAtivacoes[a].criadoEm -
        cacheRelatorioAtivacoes[b].criadoEm
    )
    .slice(
      0,
      chaves.length -
        MAX_CACHE_RELATORIO_ATIVACOES
    )
    .forEach(chave => {
      delete cacheRelatorioAtivacoes[chave];
    });
}



function normalizarTextoRelatorio(valor) {
  return String(valor || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .toUpperCase();
}

function classificarMotivoAtivacao(idMotivoInclusao) {
  const motivoId = String(idMotivoInclusao || "");

  if (motivoId === "1") {
    return "ATIVACAO";
  }

  if (motivoId === "8") {
    return "REATIVACAO";
  }

  return null;
}

function vendedorPermitidoRelatorioAtivacoes(nomeVendedor) {
  const nomeNormalizado =
    normalizarTextoRelatorio(nomeVendedor);

  if (!nomeNormalizado) {
    return false;
  }

  const prefixosIgnorados = [
    "RELACIONAMENTO",
    "RELACIOMANENTO",
    "FINANCEIRO"
  ];

  return !prefixosIgnorados.some(prefixo =>
    nomeNormalizado.startsWith(prefixo)
  );
}

function nomeVendedorRelatorioAtivacoes(contrato) {
  const vendedorId =
    String(contrato.id_vendedor || "");

  return (
    vendedores[vendedorId] ||
    contrato.vendedor ||
    contrato.nome_vendedor ||
    contrato.vendedor_nome ||
    `Vendedor não mapeado - ID ${vendedorId || "0"}`
  );
}

async function obterPlanoRelatorioAtivacoes(idPlano) {
  const planoId = String(idPlano || "");

  if (!planoId || planoId === "0") {
    return null;
  }

  if (cachePlanosRelatorioAtivacoes[planoId]) {
    return cachePlanosRelatorioAtivacoes[planoId];
  }

  try {
    const retorno = await buscar(
      "vd_contratos",
      "vd_contratos.id",
      planoId,
      "1"
    );

    const plano =
      retorno.registros?.[0] || null;

    cachePlanosRelatorioAtivacoes[planoId] =
      plano;

    return plano;
  } catch (erro) {
    console.error(
      `[RELATORIO ATIVACOES] Erro ao buscar plano ${planoId}:`,
      erro.response?.data || erro.message
    );

    return null;
  }
}

async function obterFilialRelatorioAtivacoes(idFilial) {


  const filialId = String(idFilial || "");

  if (!filialId || filialId === "0") {
    return {
      id: null,
      nome: "SEM FILIAL"
    };
  }

  if (cacheFiliaisRelatorioAtivacoes[filialId]) {
    return cacheFiliaisRelatorioAtivacoes[filialId];
  }

  try {
    const retorno = await buscar(
      "filial",
      "filial.id",
      filialId,
      "1"
    );

    const filialIXC =
      retorno.registros?.[0] || null;

      const filial = {
        id: filialId,
        nome:
          FILIAIS_COMERCIAIS[filialId] ||
          filialIXC?.razao ||
          filialIXC?.fantasia ||
          filialIXC?.nome ||
          `Filial ${filialId}`
      };

    cacheFiliaisRelatorioAtivacoes[filialId] =
      filial;

    return filial;
  } catch (erro) {
      const filial = {
        id: filialId,
        nome:
          FILIAIS_COMERCIAIS[filialId] ||
          `Filial ${filialId}`
      };

    cacheFiliaisRelatorioAtivacoes[filialId] =
      filial;

    return filial;
  }
}

function agruparRelatorioAtivacoes(
  lista,
  campoId,
  campoNome
) {
  const mapa = new Map();

  for (const item of lista) {
    const id =
      String(item[campoId] || "");

    const nome =
      item[campoNome] || "NÃO IDENTIFICADO";

    const chave = `${id}_${nome}`;

    if (!mapa.has(chave)) {
      mapa.set(chave, {
        id: id || null,
        nome,
        ativacoes: 0,
        reativacoes: 0,
        total: 0,
        receita_mensal: 0,
        taxa_instalacao: 0
      });
    }

    const registro = mapa.get(chave);

    registro.total += 1;
    registro.receita_mensal +=
      Number(item.valor_mensal || 0);

    registro.taxa_instalacao +=
      Number(item.taxa_instalacao || 0);

    if (item.tipo_movimento === "ATIVACAO") {
      registro.ativacoes += 1;
    }

    if (item.tipo_movimento === "REATIVACAO") {
      registro.reativacoes += 1;
    }
  }

  return [...mapa.values()]
    .map(item => ({
      ...item,
      receita_mensal:
        Number(item.receita_mensal.toFixed(2)),
      taxa_instalacao:
        Number(item.taxa_instalacao.toFixed(2))
    }))
    .sort((a, b) => b.total - a.total);
}


function classificarSegmentoPlano(plano, contrato = {}) {
  const nomePlano = normalizarTextoRelatorio(
    plano?.nome ||
    contrato.contrato ||
    contrato.descricao_aux_plano_venda ||
    ""
  );

  if (
    nomePlano.includes("DEDICATED") ||
    nomePlano.includes("LINK DEDICADO")
  ) {
    return "LINK_DEDICADO";
  }

  if (
    nomePlano.includes("REDE NEUTRA") ||
    nomePlano.includes("FIBRASIL")
  ) {
    return "REDE_NEUTRA";
  }

  if (
    nomePlano.includes("EMPLOYEE") ||
    nomePlano.includes("FUNCIONARIO")
  ) {
    return "FUNCIONARIO";
  }

  if (
    nomePlano.includes("CORPORATE") ||
    nomePlano.includes("ENTERPRISE") ||
    String(contrato.tipo_pessoa || "").toUpperCase() === "J"
  ) {
    return "EMPRESARIAL";
  }

  if (
    nomePlano.includes("BASIC") ||
    nomePlano.includes("PROMOTION") ||
    nomePlano.includes("PRIME") ||
    nomePlano.includes("RISE") ||
    nomePlano.includes("SPEED") ||
    nomePlano.includes("PIX")
  ) {
    return "RESIDENCIAL";
  }

  return "OUTROS";
}

async function mapearComConcorrencia(
  lista,
  limite,
  processar
) {
  const resultados =
    new Array(lista.length);

  let proximoIndice = 0;

  async function trabalhador() {
    while (true) {
      const indice = proximoIndice;
      proximoIndice += 1;

      if (indice >= lista.length) {
        return;
      }

      resultados[indice] =
        await processar(
          lista[indice],
          indice
        );
    }
  }

  const quantidadeTrabalhadores =
    Math.min(
      Math.max(1, limite),
      lista.length
    );

  await Promise.all(
    Array.from(
      {
        length: quantidadeTrabalhadores
      },
      () => trabalhador()
    )
  );

  return resultados;
}

async function montarRelatorioAtivacoes(
  dataInicial,
  dataFinal
) {
  const datasPeriodo =
    gerarDatasPeriodo(dataInicial, dataFinal);

  let contratos = [];

  for (const data of datasPeriodo) {
    const retorno = await buscar(
      "cliente_contrato",
      "cliente_contrato.data_ativacao",
      data,
      "1000"
    );

    contratos.push(...(retorno.registros || []));
  }

  const contratosUnicos = new Map();

  for (const contrato of contratos) {
    const contratoId =
      String(contrato.id || "");

    if (!contratoId) continue;

    contratosUnicos.set(
      contratoId,
      contrato
    );
  }

  contratos =
    [...contratosUnicos.values()];

  const registrosProcessados =
    await mapearComConcorrencia(
      contratos,
      6,
      async contrato => {
        const tipoMovimento =
          classificarMotivoAtivacao(
            contrato.id_motivo_inclusao
          );

        if (!tipoMovimento) {
          return null;
        }

        const vendedorId =
          String(
            contrato.id_vendedor || ""
          );

        const vendedorNome =
          nomeVendedorRelatorioAtivacoes(
            contrato
          );

        if (
          !vendedorPermitidoRelatorioAtivacoes(
            vendedorNome
          )
        ) {
          return null;
        }

        const [cliente, plano, filial] =
          await Promise.all([
            buscarClienteCache(
              contrato.id_cliente
            ),

            obterPlanoRelatorioAtivacoes(
              contrato.id_vd_contrato
            ),

            obterFilialRelatorioAtivacoes(
              contrato.id_filial
            )
          ]);

        const cidadeId =
          String(
            cliente?.cidade ||
            contrato.id_cidade ||
            contrato.cidade ||
            ""
          );

        const cidadeNome =
          await buscarCidadeIXCCache(
            cidadeId
          );

        const valorMensal =
          numeroIXC(
            contrato.valor_contrato ||
            contrato.valor ||
            plano?.valor_contrato
          );

        const taxaInstalacao =
          numeroIXC(
            contrato.taxa_instalacao
          );

        return {
          contrato_id:
            String(contrato.id),

          cliente_id:
            String(
              contrato.id_cliente || ""
            ),

          cliente:
            cliente?.razao ||
            cliente?.nome ||
            cliente?.fantasia ||
            `Cliente ID ${contrato.id_cliente}`,

          data_ativacao:
            String(
              contrato.data_ativacao || ""
            ).slice(0, 10),

          motivo_inclusao_id:
            String(
              contrato.id_motivo_inclusao ||
              ""
            ),

          tipo_movimento:
            tipoMovimento,

          vendedor_id:
            vendedorId,

          vendedor:
            vendedorNome,

          filial_id:
            filial.id,

          filial:
            filial.nome,

          cidade_id:
            cidadeId || null,

          cidade:
            cidadeNome || "-",

          bairro:
            cliente?.bairro ||
            contrato.bairro ||
            "-",

          plano_id:
            String(
              contrato.id_vd_contrato || ""
            ),

          plano:
            plano?.nome ||
            contrato.contrato ||
            contrato.descricao_aux_plano_venda ||
            "-",

          segmento:
            classificarSegmentoPlano(
              plano,
              contrato
            ),

          valor_mensal:
            Number(
              valorMensal.toFixed(2)
            ),

          taxa_instalacao:
            Number(
              taxaInstalacao.toFixed(2)
            ),

          status_contrato:
            String(
              contrato.status || "-"
            ),

          status_acesso:
            String(
              contrato.status_internet || "-"
            ),

          situacao:
            classificarSituacaoContrato(
              contrato
            ),

          tipo_pessoa:
            cliente?.tipo_pessoa ||
            cliente?.tipo_pessoa_cliente ||
            null,

          tipo_cliente_id:
            cliente?.id_tipo_cliente ||
            null,

          tipo_cliente:
            cliente?.tipo_cliente ||
            cliente?.tipo ||
            null
        };
      }
    );

  const registros =
    registrosProcessados.filter(Boolean);

  const totalAtivacoes =
    registros.filter(
      item =>
        item.tipo_movimento === "ATIVACAO"
    ).length;

  const totalReativacoes =
    registros.filter(
      item =>
        item.tipo_movimento === "REATIVACAO"
    ).length;

  const receitaMensal =
    registros.reduce(
      (soma, item) =>
        soma + Number(item.valor_mensal || 0),
      0
    );

  const taxaInstalacao =
    registros.reduce(
      (soma, item) =>
        soma + Number(item.taxa_instalacao || 0),
      0
    );

  const vendedoresUnicos =
    new Set(
      registros.map(item => item.vendedor_id)
    );

  const cidadesUnicas =
    new Set(
      registros.map(item => item.cidade_id)
    );

  const filiaisUnicas =
    new Set(
      registros.map(item => item.filial_id)
    );

  const ticketMedio =
    registros.length
      ? receitaMensal / registros.length
      : 0;

  return {
    periodo: {
      inicio: dataInicial,
      fim: dataFinal
    },

    resumo: {
      total_registros:
        registros.length,

      total_ativacoes:
        totalAtivacoes,

      total_reativacoes:
        totalReativacoes,

      receita_mensal:
        Number(receitaMensal.toFixed(2)),

      taxa_instalacao:
        Number(taxaInstalacao.toFixed(2)),

      ticket_medio:
        Number(ticketMedio.toFixed(2)),

      total_vendedores:
        vendedoresUnicos.size,

      total_cidades:
        cidadesUnicas.size,

      total_filiais:
        filiaisUnicas.size
    },

    agrupamentos: {
      vendedores:
        agruparRelatorioAtivacoes(
          registros,
          "vendedor_id",
          "vendedor"
        ),

      filiais:
        agruparRelatorioAtivacoes(
          registros,
          "filial_id",
          "filial"
        ),

      cidades:
        agruparRelatorioAtivacoes(
          registros,
          "cidade_id",
          "cidade"
        ),

      planos:
        agruparRelatorioAtivacoes(
          registros,
          "plano_id",
          "plano"
        )
    },

    registros
  };
}


app.get( "/api/relatorios-comerciais/ativacoes", exigirLogin, exigirPermissao("ver_relatorios_comerciais"), async (req, res) => {
    try {
      const inicio =
        String(req.query.inicio || "");

      const fim =
        String(req.query.fim || "");

      if (
        !/^\d{4}-\d{2}-\d{2}$/.test(inicio) ||
        !/^\d{4}-\d{2}-\d{2}$/.test(fim)
      ) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "Informe início e fim no formato YYYY-MM-DD."
        });
      }

      if (inicio > fim) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "A data inicial não pode ser maior que a data final."
        });
      }

      const inicioDate =
        new Date(`${inicio}T00:00:00`);

      const fimDate =
        new Date(`${fim}T00:00:00`);

      const diferencaDias =
        Math.floor(
          (
            fimDate.getTime() -
            inicioDate.getTime()
          ) /
          (1000 * 60 * 60 * 24)
        );

      if (diferencaDias > 62) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "Consulte no máximo 63 dias por vez nesta primeira versão."
        });
      }

      const chaveCache =
        `${inicio}_${fim}`;

      limparCacheRelatorioAtivacoes();

          const cache =
            cacheRelatorioAtivacoes[chaveCache];

          if (
            cache &&
            Date.now() - cache.criadoEm <
              TEMPO_CACHE_RELATORIO_ATIVACOES_MS
          ) {
            return res.json({
              ...cache.dados,
              cache: true,
              atualizado_em:
                new Date(cache.criadoEm)
                  .toLocaleString("pt-BR")
            });
          }

          if (
            consultasRelatorioAtivacoesEmAndamento
              .has(chaveCache)
          ) {
            const dados =
              await consultasRelatorioAtivacoesEmAndamento
                .get(chaveCache);

            return res.json({
              ...dados,
              cache: true,
              compartilhado: true,
              atualizado_em:
                new Date()
                  .toLocaleString("pt-BR")
            });
          }

          const consulta = montarRelatorioAtivacoes(
            inicio,
            fim
          );

          consultasRelatorioAtivacoesEmAndamento.set(
            chaveCache,
            consulta
          );

          try {
            const dados = await consulta;

            const criadoEm = Date.now();

            cacheRelatorioAtivacoes[chaveCache] = {
              criadoEm,
              dados
            };

            limparCacheRelatorioAtivacoes();

            return res.json({
              ...dados,
              cache: false,
              atualizado_em:
                new Date(criadoEm)
                  .toLocaleString("pt-BR")
            });
          } finally {
            consultasRelatorioAtivacoesEmAndamento.delete(
              chaveCache
            );
          }
    } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao gerar relatório comercial de ativações"
      );
    }
  }
);

// =========================================================
// RELATÓRIOS COMERCIAIS - CHURN COMERCIAL
// =========================================================


function dataIXCValida(valor) {
  const data = String(valor || "").slice(0, 10);

  return (
    /^\d{4}-\d{2}-\d{2}$/.test(data) &&
    data !== "0000-00-00"
  );
}

function calcularDiasEntreDatas(
  dataInicial,
  dataFinal
) {
  if (
    !dataIXCValida(dataInicial) ||
    !dataIXCValida(dataFinal)
  ) {
    return null;
  }

  const inicio =
    new Date(`${String(dataInicial).slice(0, 10)}T00:00:00`);

  const fim =
    new Date(`${String(dataFinal).slice(0, 10)}T00:00:00`);

  if (
    Number.isNaN(inicio.getTime()) ||
    Number.isNaN(fim.getTime())
  ) {
    return null;
  }

  const diferenca =
    Math.floor(
      (fim.getTime() - inicio.getTime()) /
      (1000 * 60 * 60 * 24)
    );

  return diferenca >= 0
    ? diferenca
    : null;
}

function classificarFaixaCancelamento(
  diasPermanencia
) {
  const dias =
    Number(diasPermanencia);

  if (!Number.isFinite(dias)) {
    return "NAO_IDENTIFICADO";
  }

  if (dias <= 30) {
    return "ATE_30_DIAS";
  }

  if (dias <= 60) {
    return "DE_31_A_60_DIAS";
  }

  if (dias <= 90) {
    return "DE_61_A_90_DIAS";
  }

  return "ACIMA_DE_90_DIAS";
}

function classificarCategoriaCancelamentoPorTexto(
  contrato
) {
  const texto =
    normalizarTextoRelatorio(
      contrato.obs_cancelamento ||
      ""
    );

  if (
    texto.includes("INADIMPL") ||
    texto.includes("FINANCEIR") ||
    texto.includes("FALTA DE PAGAMENTO") ||
    texto.includes("NAO PAGAMENTO")
  ) {
    return "INADIMPLENCIA";
  }

  if (
    texto.includes("INSATISFAC") ||
    texto.includes("RECLAMAC") ||
    texto.includes("QUALIDADE") ||
    texto.includes("INSTABILIDADE") ||
    texto.includes("LENTIDAO")
  ) {
    return "INSATISFACAO";
  }

  if (
    texto.includes("MUDANCA") ||
    texto.includes("MUDOU") ||
    texto.includes("ENDERECO")
  ) {
    return "MUDANCA_DE_ENDERECO";
  }

  if (
    texto.includes("CONCORRENT") ||
    texto.includes("OUTRO PROVEDOR")
  ) {
    return "CONCORRENCIA";
  }

  if (
    texto.includes("SEM VIABILIDADE") ||
    texto.includes("INVIABILIDADE")
  ) {
    return "INVIABILIDADE";
  }

  return "OUTROS";
}

const CLASSIFICACAO_MOTIVOS_CANCELAMENTO = {
  "4": {
    natureza: "CHURN_REAL",
    categoria: "INADIMPLENCIA"
  },

  "9": {
    natureza: "CHURN_REAL",
    categoria: "INSATISFACAO_CONEXAO"
  },

  "10": {
    natureza: "CHURN_REAL",
    categoria: "INSATISFACAO_FINANCEIRO"
  },

  "11": {
    natureza: "CHURN_REAL",
    categoria: "INSATISFACAO_ATENDIMENTO"
  },

  "15": {
    natureza: "CHURN_REAL",
    categoria: "CONCORRENCIA"
  },

  "57": {
    natureza: "CHURN_REAL",
    categoria: "MUDANCA_SEM_VIABILIDADE"
  },

  "241": {
    natureza: "CHURN_REAL",
    categoria: "DEMORA_MANUTENCAO"
  },

  "261": {
    natureza: "CHURN_REAL",
    categoria: "PROBLEMAS_FINANCEIROS"
  },

  "267": {
    natureza: "CHURN_REAL",
    categoria: "INSATISFACAO_COMERCIAL"
  },

  "269": {
    natureza: "CHURN_REAL",
    categoria: "INSATISFACAO_OPERACIONAL"
  },

  "7": {
    natureza: "MIGRACAO_INTERNA",
    categoria: "TROCA_TITULARIDADE"
  },

  "104": {
    natureza: "MIGRACAO_INTERNA",
    categoria: "NOVO_CONTRATO"
  },

  "141": {
    natureza: "MIGRACAO_INTERNA",
    categoria: "MIGRACAO_FIBRASIL"
  },

  "219": {
    natureza: "AJUSTE_ADMINISTRATIVO",
    categoria: "CONTRATO_DUPLICADO"
  },

  "235": {
    natureza: "AJUSTE_ADMINISTRATIVO",
    categoria: "TESTE"
  },

  "24": {
    natureza: "PRE_ATIVACAO",
    categoria: "NAO_ATIVADO_DE_FATO"
  },

  "210": {
    natureza: "PRE_ATIVACAO",
    categoria: "SEM_VIABILIDADE"
  },
  "12": {
  natureza: "CHURN_REAL",
  categoria: "MOTIVOS_PESSOAIS"
},

"73": {
  natureza: "CHURN_REAL",
  categoria: "MUDANCA_CONCORRENCIA"
},

"138": {
  natureza: "CHURN_REAL",
  categoria: "MUDANCA_OUTRO_ESTADO"
},

"139": {
  natureza: "CHURN_REAL",
  categoria: "MUDANCA_SEM_COBERTURA"
},

"140": {
  natureza: "CHURN_REAL",
  categoria: "MUDANCA_SEM_VIABILIDADE"
},

"188": {
  natureza: "CHURN_REAL",
  categoria: "CONCORRENCIA"
},

  "38": {
    natureza: "AJUSTE_ADMINISTRATIVO",
    categoria: "DESLIGAMENTO_FUNCIONARIO"
  },

  "114": {
    natureza: "MIGRACAO_INTERNA",
    categoria: "TROCA_TITULARIDADE"
  },

  "174": {
    natureza: "MIGRACAO_INTERNA",
    categoria: "TROCA_TITULARIDADE"
  },

  "249": {
    natureza: "CHURN_REAL",
    categoria: "FECHAMENTO_ESTABELECIMENTO"
  },

  "255": {
    natureza: "PRE_ATIVACAO",
    categoria: "DESISTENCIA_CONTRATACAO"
  }
};

function classificarCancelamentoContrato(
  contrato
) {
  const motivoId =
    String(
      contrato.motivo_cancelamento || ""
    );

  const texto =
    normalizarTextoRelatorio(
      contrato.obs_cancelamento || ""
    );

  /*
   * Motivo 180 é ambíguo:
   * pode ser desistência antes da ativação
   * ou churn real por motivos pessoais.
   */
  if (motivoId === "180") {
    if (
      texto.includes("NUNCA CHEGOU A SER ATIVO") ||
      texto.includes("NUNCA FOI ATIVADO") ||
      texto.includes("DESISTIU DA CONTRATACAO") ||
      texto.includes("DESISTENCIA DA CONTRATACAO")
    ) {
      return {
        motivo_id: motivoId,
        natureza: "PRE_ATIVACAO",
        categoria: "DESISTENCIA_CONTRATACAO",
        origem_classificacao:
          "MOTIVO_ID_E_TEXTO"
      };
    }

    return {
      motivo_id: motivoId,
      natureza: "CHURN_REAL",
      categoria: "MOTIVOS_PESSOAIS",
      origem_classificacao:
        "MOTIVO_ID_E_TEXTO"
    };
  }

  const classificacaoPorId =
    CLASSIFICACAO_MOTIVOS_CANCELAMENTO[
      motivoId
    ];

  if (classificacaoPorId) {
    return {
      motivo_id: motivoId,
      ...classificacaoPorId,
      origem_classificacao: "MOTIVO_ID"
    };
  }

  return {
    motivo_id: motivoId,
    natureza: "NAO_CLASSIFICADO",
    categoria:
      classificarCategoriaCancelamentoPorTexto(
        contrato
      ),
    origem_classificacao: "TEXTO_FALLBACK"
  };
}

const cacheRelatorioChurnComercial = {};

const consultasChurnComercialEmAndamento =
  new Map();

const TEMPO_CACHE_CHURN_COMERCIAL_MS =
  5 * 60 * 1000;

const MAX_CACHE_CHURN_COMERCIAL = 20;

function limparCacheChurnComercial() {
  const agora = Date.now();

  for (
    const [chave, item]
    of Object.entries(
      cacheRelatorioChurnComercial
    )
  ) {
    if (
      !item ||
      agora - item.criadoEm >
        TEMPO_CACHE_CHURN_COMERCIAL_MS
    ) {
      delete cacheRelatorioChurnComercial[
        chave
      ];
    }
  }

  const chaves =
    Object.keys(
      cacheRelatorioChurnComercial
    );

  if (
    chaves.length <=
    MAX_CACHE_CHURN_COMERCIAL
  ) {
    return;
  }

  chaves
    .sort(
      (a, b) =>
        cacheRelatorioChurnComercial[a]
          .criadoEm -
        cacheRelatorioChurnComercial[b]
          .criadoEm
    )
    .slice(
      0,
      chaves.length -
        MAX_CACHE_CHURN_COMERCIAL
    )
    .forEach(chave => {
      delete cacheRelatorioChurnComercial[
        chave
      ];
    });
}


function calcularMaturidadeCoorte(
  dataAtivacao
) {
  const hoje =
    new Date();

  const dataHoje =
    [
      hoje.getFullYear(),
      String(
        hoje.getMonth() + 1
      ).padStart(2, "0"),
      String(
        hoje.getDate()
      ).padStart(2, "0")
    ].join("-");

  const idadeDias =
    calcularDiasEntreDatas(
      dataAtivacao,
      dataHoje
    );

  return {
    idade_dias:
      idadeDias,

    madura_30_dias:
      Number.isFinite(idadeDias) &&
      idadeDias >= 30,

    madura_60_dias:
      Number.isFinite(idadeDias) &&
      idadeDias >= 60,

    madura_90_dias:
      Number.isFinite(idadeDias) &&
      idadeDias >= 90
  };
}


function classificarEscopoChurn({
  segmento
}) {
  const valor =
    String(segmento || "")
      .trim()
      .toUpperCase();

  if (
    valor === "RESIDENCIAL" ||
    valor === "EMPRESARIAL"
  ) {
    return "COMERCIAL";
  }

  if (
    valor === "LINK_DEDICADO" ||
    valor === "REDE_NEUTRA"
  ) {
    return "ESPECIAL";
  }

  if (
    valor === "FUNCIONARIO" ||
    valor === "INTERNO"
  ) {
    return "INTERNO";
  }

  return "OUTROS";
}


async function montarRelatorioChurnComercial(
  dataInicial,
  dataFinal
) {
  const datas =
    gerarDatasPeriodo(
      dataInicial,
      dataFinal
    );

  const contratosMap =
    new Map();

  /*
   * O período é baseado na data de ativação.
   * Portanto, buscamos os contratos ativados
   * em cada dia da coorte.
   */
  for (const data of datas) {
    const retorno =
      await buscar(
        "cliente_contrato",
        "cliente_contrato.data_ativacao",
        data,
        "1000"
      );

    for (
      const contrato
      of retorno.registros || []
    ) {
      if (!contrato.id) {
        continue;
      }

      contratosMap.set(
        String(contrato.id),
        contrato
      );
    }
  }

  const contratos =
    [...contratosMap.values()];

  const registrosProcessados =
    await mapearComConcorrencia(
      contratos,
      6,
      async contrato => {
        /*
         * Mantemos apenas ativação e
         * reativação comercial.
         */
        const tipoMovimento =
          classificarMotivoAtivacao(
            contrato.id_motivo_inclusao
          );

        if (!tipoMovimento) {
          return null;
        }

        const vendedorNome =
          nomeVendedorRelatorioAtivacoes(
            contrato
          );

        if (
          !vendedorPermitidoRelatorioAtivacoes(
            vendedorNome
          )
        ) {
          return null;
        }

        const dataAtivacao =
          String(
            contrato.data_ativacao || ""
          ).slice(0, 10);

        if (
          !dataIXCValida(
            dataAtivacao
          )
        ) {
          return null;
        }

        const dataCancelamento =
          dataIXCValida(
            contrato.data_cancelamento
          )
            ? String(
                contrato.data_cancelamento
              ).slice(0, 10)
            : null;

        const cancelado =
          Boolean(dataCancelamento);

        const diasPermanencia =
          cancelado
            ? calcularDiasEntreDatas(
                dataAtivacao,
                dataCancelamento
              )
            : null;

        const faixaCancelamento =
          cancelado
            ? classificarFaixaCancelamento(
                diasPermanencia
              )
            : "NAO_CANCELADO";

        const classificacao =
          cancelado
            ? classificarCancelamentoContrato(
                contrato
              )
            : {
                motivo_id: null,
                natureza:
                  "NAO_CANCELADO",
                categoria:
                  "NAO_CANCELADO",
                origem_classificacao:
                  null
              };

        const maturidade =
          calcularMaturidadeCoorte(
            dataAtivacao
          );

        const [
          cliente,
          plano,
          filial
        ] =
          await Promise.all([
            buscarClienteCache(
              contrato.id_cliente
            ),

            obterPlanoRelatorioAtivacoes(
              contrato.id_vd_contrato
            ),

            obterFilialRelatorioAtivacoes(
              contrato.id_filial
            )
          ]);

        const cidadeId =
          String(
            cliente?.cidade ||
            contrato.cidade ||
            ""
          );

        const cidadeNome =
          cidadeId
            ? await buscarCidadeIXCCache(
                cidadeId
              )
            : "-";

        const valorMensal =
          numeroIXC(
            contrato.valor_contrato ||
            contrato.valor ||
            plano?.valor_contrato
          );

        const taxaInstalacao =
          numeroIXC(
            contrato.taxa_instalacao
          );

          const segmento =
        classificarSegmentoPlano(
          plano,
          contrato
        );

      const escopoChurn =
        classificarEscopoChurn({
          segmento
        });

        return {
          contrato_id:
            String(contrato.id),

          cliente_id:
            String(
              contrato.id_cliente || ""
            ),

          cliente:
            cliente?.razao ||
            cliente?.nome ||
            cliente?.fantasia ||
            `Cliente ID ${contrato.id_cliente}`,

          data_ativacao:
            dataAtivacao,

          data_cancelamento:
            dataCancelamento,

          cancelado,

          dias_permanencia:
            diasPermanencia,

          faixa_cancelamento:
            faixaCancelamento,

          motivo_inclusao_id:
            String(
              contrato.id_motivo_inclusao ||
              ""
            ),

          tipo_movimento:
            tipoMovimento,

          motivo_cancelamento_id:
            cancelado
              ? String(
                  contrato
                    .motivo_cancelamento ||
                  ""
                )
              : null,

          observacao_cancelamento:
            cancelado
              ? String(
                  contrato
                    .obs_cancelamento ||
                  ""
                ).trim()
              : null,

          natureza_cancelamento:
            classificacao.natureza,

          categoria_cancelamento:
            classificacao.categoria,

          origem_classificacao:
            classificacao
              .origem_classificacao,

          vendedor_id:
            String(
              contrato.id_vendedor || ""
            ),

          vendedor:
            vendedorNome,

          filial_id:
            filial?.id ||
            String(
              contrato.id_filial || ""
            ),

          filial:
            filial?.nome ||
            "-",

          cidade_id:
            cidadeId || null,

          cidade:
            cidadeNome || "-",

          bairro:
            cliente?.bairro ||
            contrato.bairro ||
            "-",

          plano_id:
            String(
              contrato.id_vd_contrato ||
              ""
            ),

          plano:
            plano?.nome ||
            contrato.contrato ||
            contrato
              .descricao_aux_plano_venda ||
            "-",

          segmento,
          escopo_churn: escopoChurn,

          valor_mensal:
            Number(
              valorMensal.toFixed(2)
            ),

          taxa_instalacao:
            Number(
              taxaInstalacao.toFixed(2)
            ),

          responsavel_cancelamento_id:
            cancelado
              ? String(
                  contrato
                    .id_responsavel_cancelamento ||
                  ""
                )
              : null,

          origem_cancelamento:
            cancelado
              ? String(
                  contrato
                    .origem_cancelamento ||
                  ""
                )
              : null,

          parcelas_atraso:
            Number(
              contrato.num_parcelas_atraso ||
              0
            ),

          status_contrato:
            String(
              contrato.status || "-"
            ),

          status_acesso:
            String(
              contrato.status_internet ||
              "-"
            ),

          idade_coorte_dias:
            maturidade.idade_dias,

          madura_30_dias:
            maturidade
              .madura_30_dias,

          madura_60_dias:
            maturidade
              .madura_60_dias,

          madura_90_dias:
            maturidade
              .madura_90_dias
        };
      }
    );

  const registros =
    registrosProcessados.filter(Boolean);

    const motivosOutrosMap =
  new Map();

for (const item of registros) {
  if (!item.cancelado) {
    continue;
  }

  if (
    item.categoria_cancelamento !==
    "OUTROS"
  ) {
    continue;
  }

  const motivoId =
    String(
      item.motivo_cancelamento_id ||
      "SEM_ID"
    );

  if (!motivosOutrosMap.has(motivoId)) {
    motivosOutrosMap.set(motivoId, {
      motivo_id: motivoId,
      quantidade: 0,
      observacoes: []
    });
  }

  const grupo =
    motivosOutrosMap.get(motivoId);

  grupo.quantidade += 1;

  const observacao =
    String(
      item.observacao_cancelamento || ""
    ).trim();

  if (
    observacao &&
    grupo.observacoes.length < 5 &&
    !grupo.observacoes.includes(observacao)
  ) {
    grupo.observacoes.push(observacao);
  }
}

const motivosOutros =
  [...motivosOutrosMap.values()]
    .sort(
      (a, b) =>
        b.quantidade -
        a.quantidade
    );



  const cancelados =
    registros.filter(
      item => item.cancelado
    );

  const churnReal =
    cancelados.filter(
      item =>
        item.natureza_cancelamento ===
        "CHURN_REAL"
    );

  const cancelados30 =
    churnReal.filter(
      item =>
        item.faixa_cancelamento ===
        "ATE_30_DIAS"
    );

  const cancelados60 =
    churnReal.filter(
      item =>
        item.faixa_cancelamento ===
        "DE_31_A_60_DIAS"
    );

  const cancelados90 =
    churnReal.filter(
      item =>
        item.faixa_cancelamento ===
        "DE_61_A_90_DIAS"
    );

  const churnAte90 =
    churnReal.filter(
      item =>
        Number.isFinite(
          item.dias_permanencia
        ) &&
        item.dias_permanencia <= 90
    );

  /*
   * Denominadores maduros.
   * São essenciais para não comparar
   * coortes incompletas.
   */
  const coorteMadura30 =
    registros.filter(
      item => item.madura_30_dias
    );

  const coorteMadura60 =
    registros.filter(
      item => item.madura_60_dias
    );

  const coorteMadura90 =
    registros.filter(
      item => item.madura_90_dias
    );

  const churn30Maduros =
    cancelados30.filter(
      item => item.madura_30_dias
    );

  const churnAte60Maduros =
    churnReal.filter(
      item =>
        item.madura_60_dias &&
        Number.isFinite(
          item.dias_permanencia
        ) &&
        item.dias_permanencia <= 60
    );

  const churnAte90Maduros =
    churnAte90.filter(
      item => item.madura_90_dias
    );

  const calcularPercentual = (
    total,
    base
  ) => {
    if (!base) {
      return 0;
    }

    return Number(
      (
        (total / base) *
        100
      ).toFixed(2)
    );
  };

  const receitaPerdida90 =
    churnAte90.reduce(
      (total, item) =>
        total +
        numeroIXC(
          item.valor_mensal
        ),
      0
    );

  const taxaInstalacao90 =
    churnAte90.reduce(
      (total, item) =>
        total +
        numeroIXC(
          item.taxa_instalacao
        ),
      0
    );

  return {
    periodo_coorte: {
      inicio: dataInicial,
      fim: dataFinal
    },

    resumo: {
      total_ativados:
        registros.length,

      total_cancelados:
        cancelados.length,

      total_churn_real:
        churnReal.length,

      cancelados_ate_30_dias:
        cancelados30.length,

      cancelados_31_a_60_dias:
        cancelados60.length,

      cancelados_61_a_90_dias:
        cancelados90.length,

      cancelados_ate_90_dias:
        churnAte90.length,

      cancelados_acima_90_dias:
        churnReal.filter(
          item =>
            item.faixa_cancelamento ===
            "ACIMA_DE_90_DIAS"
        ).length,

      migracoes_internas:
        cancelados.filter(
          item =>
            item.natureza_cancelamento ===
            "MIGRACAO_INTERNA"
        ).length,

      pre_ativacao:
        cancelados.filter(
          item =>
            item.natureza_cancelamento ===
            "PRE_ATIVACAO"
        ).length,

      ajustes_administrativos:
        cancelados.filter(
          item =>
            item.natureza_cancelamento ===
            "AJUSTE_ADMINISTRATIVO"
        ).length,

      nao_classificados:
        cancelados.filter(
          item =>
            item.natureza_cancelamento ===
            "NAO_CLASSIFICADO"
        ).length,

      receita_mensal_perdida_90_dias:
        Number(
          receitaPerdida90.toFixed(2)
        ),

      taxa_instalacao_cancelada_90_dias:
        Number(
          taxaInstalacao90.toFixed(2)
        )
    },

    maturidade: {
      coorte_madura_30_dias:
        coorteMadura30.length,

      coorte_madura_60_dias:
        coorteMadura60.length,

      coorte_madura_90_dias:
        coorteMadura90.length,

      taxa_churn_30_dias:
        calcularPercentual(
          churn30Maduros.length,
          coorteMadura30.length
        ),

        diagnostico: {
          motivos_outros:
            motivosOutros
        },

      taxa_churn_ate_60_dias:
        calcularPercentual(
          churnAte60Maduros.length,
          coorteMadura60.length
        ),

      taxa_churn_ate_90_dias:
        calcularPercentual(
          churnAte90Maduros.length,
          coorteMadura90.length
        )
    },
    

    registros
  };
}

app.get(
  "/api/relatorios-comerciais/churn",
  exigirLogin,
  exigirPermissao(
    "ver_relatorios_comerciais"
  ),
  async (req, res) => {
    try {
      const inicio =
        String(
          req.query.inicio || ""
        );

      const fim =
        String(
          req.query.fim || ""
        );

      if (
        !dataIXCValida(inicio) ||
        !dataIXCValida(fim)
      ) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "Informe inicio e fim no formato YYYY-MM-DD."
        });
      }

      const diasPeriodo =
        calcularDiasEntreDatas(
          inicio,
          fim
        );

      if (
        diasPeriodo === null ||
        diasPeriodo < 0
      ) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "O período informado é inválido."
        });
      }

      /*
       * Mantemos a mesma proteção
       * da rota de ativações.
       */
      if (diasPeriodo > 63) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "O período máximo permitido é de 63 dias."
        });
      }

      limparCacheChurnComercial();

      const chaveCache =
        `${inicio}|${fim}`;

      const cache =
        cacheRelatorioChurnComercial[
          chaveCache
        ];

      if (
        cache &&
        Date.now() - cache.criadoEm <
          TEMPO_CACHE_CHURN_COMERCIAL_MS
      ) {
        return res.json({
          ...cache.dados,
          cache: true,
          atualizado_em:
            new Date(
              cache.criadoEm
            ).toLocaleString(
              "pt-BR"
            )
        });
      }

      if (
        consultasChurnComercialEmAndamento
          .has(chaveCache)
      ) {
        const dados =
          await consultasChurnComercialEmAndamento
            .get(chaveCache);

        return res.json({
          ...dados,
          cache: true,
          compartilhado: true,
          atualizado_em:
            new Date()
              .toLocaleString(
                "pt-BR"
              )
        });
      }

      const consulta =
        montarRelatorioChurnComercial(
          inicio,
          fim
        );

      consultasChurnComercialEmAndamento
        .set(
          chaveCache,
          consulta
        );

      try {
        const dados =
          await consulta;

        const criadoEm =
          Date.now();

        cacheRelatorioChurnComercial[
          chaveCache
        ] = {
          criadoEm,
          dados
        };

        limparCacheChurnComercial();

        return res.json({
          ...dados,
          cache: false,
          atualizado_em:
            new Date(
              criadoEm
            ).toLocaleString(
              "pt-BR"
            )
        });

      } finally {
        consultasChurnComercialEmAndamento
          .delete(chaveCache);
      }

        } catch (erro) {
          console.error(
            "\n[CHURN COMERCIAL] ERRO AO GERAR RELATÓRIO"
          );

          console.error(
            "[CHURN COMERCIAL] Mensagem:",
            erro?.message
          );

          console.error(
            "[CHURN COMERCIAL] Código:",
            erro?.code
          );

          console.error(
            "[CHURN COMERCIAL] Status externo:",
            erro?.response?.status
          );

          console.error(
            "[CHURN COMERCIAL] Resposta externa:",
            erro?.response?.data
          );

          console.error(
            "[CHURN COMERCIAL] Stack:",
            erro?.stack
          );

          return res.status(500).json({
            erro: true,
            mensagem:
              erro?.message ||
              "Não foi possível concluir a operação.",

            codigo:
              erro?.code || null,

            etapa:
              "relatorio_churn_comercial"
          });
        }
  }
);



if (process.env.NODE_ENV !== "production") {
app.get("/api/debug-os-churn", exigirLogin, exigirSuperAdmin, async (req, res) => {
  try {
    const dataInicial = req.query.inicio;
    const dataFinal = req.query.fim;

    const retornoOS = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.setor",
      "73",
      "1000"
    );

    const linhas = [];

    for (const os of retornoOS.registros || []) {
      const dataOS = String(
        os.data_fechamento ||
        os.data_final ||
        os.ultima_atualizacao ||
        ""
      ).slice(0, 10);

      if (dataOS < dataInicial || dataOS > dataFinal) continue;

      const texto = `${os.mensagem || ""}\n${os.mensagem_resposta || ""}`;

      const { planoAntigoTexto, planoNovoTexto } = extrairPlanosChurn(texto);

      linhas.push({
        os_id: os.id,
        cliente_id: os.id_cliente,
        contrato_id: os.id_contrato_kit,
        tecnico_id: os.id_tecnico,
        data: dataOS,
        status: os.status,
        plano_antigo: planoAntigoTexto,
        plano_novo: planoNovoTexto,
        tipo_detectado: planoAntigoTexto && planoNovoTexto
          ? "TEM_PADRAO"
          : "SEM_PADRAO"
      });
    }

    res.json(linhas);

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});
} 

async function montarRespostaRankingChurnPorApuracao(dataInicial, dataFinal) {
  const mesRanking = dataInicial.slice(0, 7);

  const [apuracoes] = await db.query(
    `
    SELECT *
    FROM ranking_churn_apuracao
    WHERE mes = ?
      AND ativo = 1
    `,
    [mesRanking]
  );

  if (!apuracoes.length) {
    return null;
  }

  const [metasRows] = await db.query(
    `
    SELECT vendedor_id, meta
    FROM metas_churn
    WHERE mes = ? AND ativo = 1
    `,
    [mesRanking]
  );

  const metasBanco = {};
  metasRows.forEach(item => {
    metasBanco[String(item.vendedor_id)] = Number(item.meta || 0);
  });

  const mapa = {};

  for (const item of apuracoes) {
    const vendedorId = String(item.vendedor_id || "");

    if (!mapa[vendedorId]) {
      mapa[vendedorId] = {
        vendedor_id: vendedorId,
        colaborador_ixc_id: "",
        rc_nome: item.rc_nome,
        renovacoes: 0,
        receita_renovada: 0,
        upgrades: 0,
        downgrades: 0,
        manteve: 0,
        nao_identificado: 0,
        ticket_medio: 0,
        itens: []
      };
    }

    const registro = mapa[vendedorId];
    const tipo = String(item.tipo_renovacao || "NAO_IDENTIFICADO").toUpperCase();

    if (tipo === "NAO_IDENTIFICADO") {
        continue;
      }

    const valorNovo = Number(item.valor_novo || 0);

    registro.renovacoes += 1;
    registro.receita_renovada += valorNovo;

    if (tipo === "UPGRADE") {
      registro.upgrades += 1;
    } else if (tipo === "DOWNGRADE") {
      registro.downgrades += 1;
    } else if (tipo === "MANTEVE") {
      registro.manteve += 1;
    } else {
      registro.nao_identificado += 1;
    }

    registro.itens.push({
      rc_nome: item.rc_nome,
      vendedor_id: vendedorId,
      contrato_id: item.contrato_id,
      cliente_id: item.cliente_id,
      cliente: item.cliente || "-",
      data_renovacao: item.mes,
      plano_id: "",
      plano: "-",
      valor_renovado: valorNovo,
      tipo_renovacao: tipo
    });
  }

  const ranking = Object.values(mapa)
    .map(item => {
      const receita = Number(item.receita_renovada.toFixed(2));
      const meta = metasBanco[String(item.vendedor_id)] || 0;
      const falta = Math.max(meta - receita, 0);
      const percentual = meta ? (receita / meta) * 100 : 0;

      return {
        ...item,
        receita_renovada: receita,
        ticket_medio: item.renovacoes
          ? Number((receita / item.renovacoes).toFixed(2))
          : 0,
        meta: Number(meta.toFixed(2)),
        percentual_meta: Number(percentual.toFixed(2)),
        falta_meta: Number(falta.toFixed(2))
      };
    })
    .sort((a, b) => b.receita_renovada - a.receita_renovada)
    .map((item, index) => ({
      ...item,
      posicao: index + 1
    }));

  const resposta = {
    periodo: {
      inicio: dataInicial,
      fim: dataFinal
    },
    origem: "apuracao_banco",
    total_contratos_churn: ranking.reduce((soma, item) => soma + item.renovacoes, 0),
    total_renovacoes: ranking.reduce((soma, item) => soma + item.renovacoes, 0),
    receita_total: Number(
      ranking.reduce((soma, item) => soma + item.receita_renovada, 0).toFixed(2)
    ),
    ranking,
    cache: false
  };

  resposta.relatorio_clientes = ranking.flatMap(item =>
    item.itens.map(cliente => ({
      posicao: item.posicao,
      rc_nome: item.rc_nome,
      vendedor_id: item.vendedor_id,
      contrato_id: cliente.contrato_id,
      cliente_id: cliente.cliente_id,
      cliente: cliente.cliente,
      data_renovacao: cliente.data_renovacao,
      plano: cliente.plano,
      valor_renovado: cliente.valor_renovado,
      tipo_renovacao: cliente.tipo_renovacao
    }))
  );

  return resposta;
}

app.post("/api/ranking-churn/importar-apuracao", exigirLogin, exigirPermissao("gerenciar_metas"), async (req, res) => {
  try {
    const { mes } = req.body || {};

    if (!mes || !/^\d{4}-\d{2}$/.test(mes)) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe o mês no formato YYYY-MM."
      });
    }

    const usuarioLogado = req.session.usuario;

    if (!podeGerenciarMetas(usuarioLogado)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso negado."
      });
    }

    const dataInicial = `${mes}-01`;
    const ultimoDia = new Date(Number(mes.slice(0, 4)), Number(mes.slice(5, 7)), 0)
      .getDate();

    const dataFinal = `${mes}-${String(ultimoDia).padStart(2, "0")}`;

    const [rcRows] = await db.query(`
      SELECT rc_nome, vendedor_id, colaborador_ixc_id
      FROM colaboradores_churn
      WHERE colaborador_ixc_id IS NOT NULL
        AND ativo = 1
    `);

    const mapaRC = {};
    rcRows.forEach(rc => {
      mapaRC[String(rc.colaborador_ixc_id)] = rc;
    });

    const retornoOS = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.setor",
      "73",
      "1000"
    );

    let importados = 0;
    let identificados = 0;
    let naoIdentificados = 0;

    for (const os of retornoOS.registros || []) {
      const dataOS = String(
        os.data_fechamento ||
        os.data_final ||
        os.ultima_atualizacao ||
        ""
      ).slice(0, 10);

      if (dataOS < dataInicial || dataOS > dataFinal) continue;
      if (String(os.status) !== "F") continue;

      const rc = mapaRC[String(os.id_tecnico || "")];

      if (!rc) continue;

      const texto = `${os.mensagem || ""}\n${os.mensagem_resposta || ""}`;

      const matchAntigo = texto.match(/PLANO\s+ANTIGO:[\s\S]*?VALOR:\s*R\$\s*([\d.,]+)/i);
      const matchNovo = texto.match(/PLANO\s+NOVO:[\s\S]*?VALOR:\s*R\$\s*([\d.,]+)/i);

      const valorAntigo = matchAntigo ? numeroIXC(matchAntigo[1]) : null;
      const valorNovo = matchNovo ? numeroIXC(matchNovo[1]) : 0;

      let tipoRenovacao = "NAO_IDENTIFICADO";

      if (valorAntigo && valorNovo) {
        if (valorNovo > valorAntigo) tipoRenovacao = "UPGRADE";
        else if (valorNovo < valorAntigo) tipoRenovacao = "DOWNGRADE";
        else tipoRenovacao = "MANTEVE";
      }

      if (tipoRenovacao === "NAO_IDENTIFICADO") {
        naoIdentificados += 1;
      } else {
        identificados += 1;
      }

      const cliente = await buscarClienteCache(os.id_cliente);

      await db.query(
        `
        INSERT INTO ranking_churn_apuracao
          (
            mes,
            os_id,
            contrato_id,
            cliente_id,
            cliente,
            vendedor_id,
            rc_nome,
            valor_antigo,
            valor_novo,
            tipo_renovacao,
            origem,
            observacao,
            ativo
          )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON DUPLICATE KEY UPDATE
          contrato_id = VALUES(contrato_id),
          cliente_id = VALUES(cliente_id),
          cliente = VALUES(cliente),
          vendedor_id = VALUES(vendedor_id),
          rc_nome = VALUES(rc_nome),
          valor_antigo = VALUES(valor_antigo),
          valor_novo = VALUES(valor_novo),
          tipo_renovacao = VALUES(tipo_renovacao),
          origem = VALUES(origem),
          observacao = VALUES(observacao),
          ativo = 1
        `,
        [
          mes,
          String(os.id),
          String(os.id_contrato_kit || ""),
          String(os.id_cliente || ""),
          cliente?.razao || cliente?.nome || `Cliente ID ${os.id_cliente}`,
          String(rc.vendedor_id),
          rc.rc_nome,
          valorAntigo,
          valorNovo,
          tipoRenovacao,
          tipoRenovacao === "NAO_IDENTIFICADO" ? "revisao_manual" : "sistema",
          tipoRenovacao === "NAO_IDENTIFICADO"
            ? "Importado sem valor antigo/novo identificado no template."
            : null
        ]
      );

      importados += 1;
    }

    delete cacheRankingChurn[`${dataInicial}_${dataFinal}`];

    res.json({
      sucesso: true,
      mensagem: "Apuração Churn importada com sucesso.",
      mes,
      importados,
      identificados,
      nao_identificados: naoIdentificados
    });

  } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao importar apuração Churn"
      );
  }
});


  app.get("/api/ranking-churn", exigirLogin, async (req, res) => {
    try {
      const dataInicial = req.query.inicio;
      const dataFinal = req.query.fim;

      if (!dataInicial || !dataFinal) {
        return res.status(400).json({
          erro: true,
          mensagem: "Informe inicio e fim no formato YYYY-MM-DD."
        });
      }

      const respostaApuracao = await montarRespostaRankingChurnPorApuracao(
        dataInicial,
        dataFinal
      );

      if (respostaApuracao) {
        return res.json(respostaApuracao);
      }

      const chaveCache = `${dataInicial}_${dataFinal}`;
      const cache = cacheRankingChurn[chaveCache];

      // Depois que estabilizar, pode reativar o cache.
      // if (cache && Date.now() - cache.criadoEm < TEMPO_CACHE_CHURN_MS) {
      //   return res.json({
      //     ...cache.dados,
      //     cache: true
      //   });
      // }

            const [rcRows] = await db.query(`
              SELECT rc_nome, vendedor_id, colaborador_ixc_id, ativo
              FROM colaboradores_churn
              WHERE colaborador_ixc_id IS NOT NULL
                AND ativo = 1
            `);


          const mapa = {};

      const datasPeriodo = gerarDatasPeriodo(dataInicial, dataFinal);
      let contratos = [];

      for (const data of datasPeriodo) {
        const retornoContratos = await buscar(
          "cliente_contrato",
          "cliente_contrato.data_renovacao",
          data,
          "1000"
        );

        contratos.push(...(retornoContratos.registros || []));
      }

          const idsColaboradoresChurn = rcRows
            .map(rc => String(rc.colaborador_ixc_id || ""))
            .filter(Boolean);

          const retornoOSChurn = await buscar(
            "su_oss_chamado",
            "su_oss_chamado.setor",
            "73",
            "1000"
          );

          const mapaOSPorContrato = {};
          const mapaOSPorClienteData = {};

          for (const os of retornoOSChurn.registros || []) {
            const idTecnicoOS = String(os.id_tecnico || "");
            if (!idsColaboradoresChurn.includes(idTecnicoOS)) continue;

            const dataOS = String(
              os.data_fechamento ||
              os.data_final ||
              os.ultima_atualizacao ||
              ""
            ).slice(0, 10);

            if (dataOS < dataInicial || dataOS > dataFinal) continue;

            const texto = `${os.mensagem || ""}\n${os.mensagem_resposta || ""}`;
            const tipo = await classificarRenovacaoChurnPorTexto(texto);

            const contratoId = String(os.id_contrato_kit || "");
            const clienteId = String(os.id_cliente || "");

            if (tipo === "NAO_IDENTIFICADO") continue;

            if (contratoId) {
              mapaOSPorContrato[contratoId] = tipo;
            }

            if (clienteId && dataOS) {
              mapaOSPorClienteData[`${clienteId}_${dataOS}`] = tipo;
            }
          }

      const idsStatusAcessoValidos = ["A", "FA"];

      for (const contrato of contratos) {
        const idVendedor = String(contrato.id_vendedor || "");

        if (String(contrato.status) !== "A") continue;

        if (!idsStatusAcessoValidos.includes(String(contrato.status_internet))) {
          continue;
        }

        const rc = rcRows.find(item =>
          String(item.vendedor_id) === idVendedor
        );

        if (!rc) continue;

        const idPlano = contrato.id_vd_contrato;
        const plano = await obterPlanoChurnPorId(idPlano);

        const receitaRenovada = numeroIXC(
          plano?.valor_contrato || contrato.valor_contrato
        );

          const dataRenovacaoContrato = String(contrato.data_renovacao || "").slice(0, 10);

          const tipoRenovacao =
            mapaOSPorContrato[String(contrato.id)] ||
            mapaOSPorClienteData[`${String(contrato.id_cliente)}_${dataRenovacaoContrato}`] ||
            "NAO_IDENTIFICADO";

            if (tipoRenovacao === "NAO_IDENTIFICADO") {
              continue;
            }

                  if (!mapa[idVendedor]) {
                    mapa[idVendedor] = {
                      vendedor_id: idVendedor,
                      colaborador_ixc_id: String(rc.colaborador_ixc_id || ""),
                      rc_nome: rc.rc_nome,
                      renovacoes: 0,
                      receita_renovada: 0,
                      upgrades: 0,
                      downgrades: 0,
                      manteve: 0,
                      nao_identificado: 0,
                      ticket_medio: 0,
                      itens: []
                    };
                  }

                  const registro = mapa[idVendedor];


            
            registro.renovacoes += 1;
            registro.receita_renovada += receitaRenovada;

            if (tipoRenovacao === "UPGRADE") {
              registro.upgrades += 1;
            } else if (tipoRenovacao === "DOWNGRADE") {
              registro.downgrades += 1;
            } else if (tipoRenovacao === "MANTEVE") {
              registro.manteve += 1;
            } else {
              registro.nao_identificado += 1;
            }

          registro.itens.push({
            rc_nome: rc.rc_nome,
            vendedor_id: idVendedor,
            contrato_id: contrato.id,
            cliente_id: contrato.id_cliente,
            cliente: contrato.razao || contrato.cliente || contrato.nome_cliente || "-",
            data_renovacao: contrato.data_renovacao,
            plano_id: idPlano,
            plano: plano?.nome || contrato.contrato || "-",
            valor_renovado: receitaRenovada,
            tipo_renovacao: tipoRenovacao
          });
      }

      const mesRanking = dataInicial.slice(0, 7);

      const [metasRows] = await db.query(
        `
        SELECT vendedor_id, meta
        FROM metas_churn
        WHERE mes = ? AND ativo = 1
        `,
        [mesRanking]
      );

      const metasBanco = {};
      metasRows.forEach(item => {
        metasBanco[String(item.vendedor_id)] = Number(item.meta || 0);
      });

      const ranking = Object.values(mapa)
        .map(item => {
          const receita = Number(item.receita_renovada.toFixed(2));
          const meta = metasBanco[String(item.vendedor_id)] || 0;
          const falta = Math.max(meta - receita, 0);
          const percentual = meta ? (receita / meta) * 100 : 0;

          return {
            ...item,
            receita_renovada: receita,
            ticket_medio: item.renovacoes
              ? Number((receita / item.renovacoes).toFixed(2))
              : 0,
            meta: Number(meta.toFixed(2)),
            percentual_meta: Number(percentual.toFixed(2)),
            falta_meta: Number(falta.toFixed(2))
          };
        })
        .sort((a, b) => b.receita_renovada - a.receita_renovada)
        .map((item, index) => ({
          ...item,
          posicao: index + 1
        }));

      const resposta = {
        periodo: {
          inicio: dataInicial,
          fim: dataFinal
        },
        total_contratos_churn: ranking.reduce(
          (soma, item) => soma + item.renovacoes,
          0
        ),
        total_renovacoes: ranking.reduce(
          (soma, item) => soma + item.renovacoes,
          0
        ),
        receita_total: Number(
          ranking.reduce((soma, item) => soma + item.receita_renovada, 0).toFixed(2)
        ),
        ranking,
        cache: false
      };

      cacheRankingChurn[chaveCache] = {
        criadoEm: Date.now(),
        dados: resposta
      };


      resposta.relatorio_clientes = ranking.flatMap(item =>
            item.itens.map(cliente => ({
              posicao: item.posicao,
              rc_nome: item.rc_nome,
              vendedor_id: item.vendedor_id,
              contrato_id: cliente.contrato_id,
              cliente_id: cliente.cliente_id,
              cliente: cliente.cliente,
              data_renovacao: cliente.data_renovacao,
              plano: cliente.plano,
              valor_renovado: cliente.valor_renovado,
              tipo_renovacao: cliente.tipo_renovacao
            }))
          );


      res.json(resposta);

    } catch (erro) {
      res.status(500).json({
        erro: true,
        status: erro.response?.status || null,
        mensagem: erro.response?.data || erro.message
      });
    }
  });

  // RANKING BACKOFFICE //

function usuarioPodeEditarPenalidadeBackoffice(req) {
  const usuario = req.session?.usuario || {};
  const permissoes = usuario.permissoes || [];

  return (
    usuario.perfil === "super_admin" ||
    permissoes.includes("editar_penalidades_backoffice")
  );
}

async function registrarPenalidadeBackoffice({
  osId,
  colaboradorIxcId,
  cliente,
  contratoId,
  dataCadastro,
  dataBoleto,
  boletoId,
  motivo,
  observacao,
  origem,
  usuarioId,
  usuarioNome
}) {
  await db.query(
    `
    INSERT INTO penalidades_backoffice
      (
        os_id,
        colaborador_ixc_id,
        cliente,
        contrato_id,
        data_cadastro,
        data_boleto,
        boleto_id,
        motivo,
        observacao,
        origem,
        criado_por_usuario_id,
        criado_por_nome,
        desconsiderada
      )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    ON DUPLICATE KEY UPDATE
      cliente = VALUES(cliente),
      contrato_id = VALUES(contrato_id),
      data_cadastro = VALUES(data_cadastro),
      data_boleto = VALUES(data_boleto),
      boleto_id = VALUES(boleto_id),
      motivo = VALUES(motivo),
      observacao = VALUES(observacao),
      atualizado_em = CURRENT_TIMESTAMP
    `,
    [
      String(osId),
      String(colaboradorIxcId),
      cliente || "-",
      contratoId || null,
      dataCadastro || null,
      dataBoleto || null,
      boletoId || null,
      motivo,
      observacao || null,
      origem || "GESTOR",
      usuarioId || null,
      usuarioNome || origem || null
    ]
  );
}


app.post("/api/ranking-backoffice/penalidades", exigirLogin, async (req, res) => {
  try {
    if (!usuarioPodeEditarPenalidadeBackoffice(req)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Você não tem permissão para lançar penalidades BackOffice."
      });
    }

    const {
      os_id,
      colaborador_ixc_id,
      cliente,
      contrato_id,
      data_cadastro,
      motivo,
      observacao
    } = req.body || {};

    if (!os_id || !colaborador_ixc_id || !motivo || !String(motivo).trim()) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe O.S., colaborador e motivo da penalidade."
      });
    }

    await registrarPenalidadeBackoffice({
      osId: os_id,
      colaboradorIxcId: colaborador_ixc_id,
      cliente,
      contratoId: contrato_id,
      dataCadastro: data_cadastro || null,
      dataBoleto: null,
      boletoId: null,
      motivo: String(motivo).trim(),
      observacao: String(observacao || "").trim() || null,
      origem: "GESTOR",
      usuarioId: req.session.usuario?.id || null,
      usuarioNome: req.session.usuario?.nome || req.session.usuario?.usuario || null
    });

    return res.json({
      sucesso: true,
      mensagem: "Penalidade lançada com sucesso."
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

app.patch("/api/ranking-backoffice/penalidades/:id/desconsiderar", exigirLogin, async (req, res) => {
  try {
    if (!usuarioPodeEditarPenalidadeBackoffice(req)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Você não tem permissão para desconsiderar penalidades BackOffice."
      });
    }

    const { desconsiderada, motivo_desconsideracao } = req.body || {};
    const desconsiderar = desconsiderada ? 1 : 0;
    const motivo = String(motivo_desconsideracao || "").trim();

    if (desconsiderar && !motivo) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe o motivo para desconsiderar a penalidade."
      });
    }

    await db.query(
      `
      UPDATE penalidades_backoffice
      SET
        desconsiderada = ?,
        motivo_desconsideracao = ?,
        desconsiderado_por_usuario_id = ?,
        desconsiderado_por_nome = ?,
        desconsiderado_em = CASE WHEN ? = 1 THEN NOW() ELSE NULL END
      WHERE id = ?
      `,
      [
        desconsiderar,
        desconsiderar ? motivo : null,
        desconsiderar ? req.session.usuario?.id || null : null,
        desconsiderar ? req.session.usuario?.nome || req.session.usuario?.usuario || null : null,
        desconsiderar,
        req.params.id
      ]
    );

    return res.json({
      sucesso: true,
      mensagem: desconsiderar
        ? "Penalidade desconsiderada."
        : "Penalidade reativada."
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

let syncPenalidadesBackofficeRodando = false;
let ultimaSyncPenalidadesBackoffice = null;
const INTERVALO_SYNC_PENALIDADES_BACKOFFICE = 10 * 60 * 1000;

async function sincronizarPenalidadesBackOffice(inicio, fim) {
  if (!inicio || !fim) {
    throw new Error("Informe inicio e fim no formato YYYY-MM-DD.");
  }

  const retornoOS = await buscar(
    "su_oss_chamado",
    "su_oss_chamado.id_assunto",
    "2",
    "1000"
  );

  const ordens = retornoOS.registros || [];

    const [backofficeRows] = await db.query(`
    SELECT colaborador_ixc_id
    FROM colaboradores_backoffice
    WHERE ativo = 1
  `);

  const idsBackofficeValidos = new Set(
    backofficeRows.map(item => String(item.colaborador_ixc_id))
  );

  const osCadastroFinalizadas = ordens.filter(os => {
    const dataFechamento = String(
      os.data_fechamento ||
      os.data_final ||
      os.ultima_atualizacao ||
      ""
    ).slice(0, 10);

    return (
      String(os.status) === "F" &&
      String(os.id_assunto) === "2" &&
      dataFechamento >= inicio &&
      dataFechamento <= fim
    );
  });

  for (const os of osCadastroFinalizadas) {
    const colaboradorIxcId = String(os.id_tecnico || "");

    if (!colaboradorIxcId || colaboradorIxcId === "0") continue;

        if (!idsBackofficeValidos.has(colaboradorIxcId)) {
      continue;
    }

    const dataCadastro =
      os.data_fechamento ||
      os.data_final ||
      os.ultima_atualizacao ||
      null;

    const contratoId =
      os.id_contrato_kit ||
      os.id_contrato ||
      os.contrato ||
      "";

    let nomeCliente = String(os.id_cliente || "-");

    try {
      const cliente = await buscarClienteCache(os.id_cliente);

      if (cliente) {
        nomeCliente =
          cliente.razao ||
          cliente.nome ||
          cliente.fantasia ||
          nomeCliente;
      }
    } catch (erroCliente) {
      console.log("Erro ao buscar cliente da penalidade:", os.id_cliente, erroCliente.message);
    }

    const respostaBoletos = await api.post("/fn_areceber", {
      qtype: "fn_areceber.id_cliente",
      query: String(os.id_cliente),
      oper: "=",
      page: "1",
      rp: "50",
      sortname: "id",
      sortorder: "desc"
    });

    const boletos = respostaBoletos.data?.registros || [];

    const boletosDoContrato = boletos.filter(boleto => {
      const boletoContrato =
        boleto.id_contrato_avulso ||
        boleto.id_contrato ||
        boleto.contrato ||
        "";

      if (!contratoId || !boletoContrato) return true;

      return String(boletoContrato) === String(contratoId);
    });

const dataAberturaCadastro =
  os.data_abertura ||
  os.data_inicio ||
  os.data_hora_abertura ||
  null;

      const boletoAntesCadastro = boletosDoContrato.find(boleto => {
        const dataBoletoCompleta =
          boleto.data_emissao ||
          boleto.data_cadastro ||
          boleto.data ||
          null;

        if (!dataBoletoCompleta || !dataAberturaCadastro || !dataCadastro) {
          return false;
        }

        const dataBoleto = new Date(String(dataBoletoCompleta).replace(" ", "T"));
        const dataAbertura = new Date(String(dataAberturaCadastro).replace(" ", "T"));
        const dataFechamento = new Date(String(dataCadastro).replace(" ", "T"));

        if (
          isNaN(dataBoleto.getTime()) ||
          isNaN(dataAbertura.getTime()) ||
          isNaN(dataFechamento.getTime())
        ) {
          return false;
        }

        return (
          dataBoleto >= dataAbertura &&
          dataBoleto < dataFechamento
        );
      });

    if (!boletoAntesCadastro) continue;

      const dataBoleto =
        boletoAntesCadastro.data_emissao ||
        boletoAntesCadastro.data_cadastro ||
        boletoAntesCadastro.data ||
        null;

    await registrarPenalidadeBackoffice({
      osId: os.id,
      colaboradorIxcId,
      cliente: nomeCliente,
      contratoId,
      dataCadastro,
      dataBoleto,
      boletoId: boletoAntesCadastro.id || null,
      motivo: "Boleto gerado antes da finalização do cadastro.",
      observacao: "Penalidade gerada automaticamente pelo sistema.",
      origem: "SISTEMA",
      usuarioId: null,
      usuarioNome: "Sistema"
    });
  }

  const [penalidadesBanco] = await db.query(
    `
    SELECT
      p.id,
      p.os_id,
      p.colaborador_ixc_id AS responsavel_id,
      COALESCE(u.nome, u.usuario, '-') AS responsavel_nome,
      p.cliente,
      p.contrato_id,
      p.data_cadastro,
      p.data_boleto,
      p.boleto_id,
      p.motivo,
      p.observacao,
      p.origem,
      p.desconsiderada,
      p.motivo_desconsideracao,
      p.criado_por_nome,
      p.desconsiderado_por_nome,
      p.desconsiderado_em,
      p.criado_em,
      p.atualizado_em
    FROM penalidades_backoffice p
    LEFT JOIN usuarios_dashboard u
      ON CAST(u.colaborador_ixc_id AS CHAR) = CAST(p.colaborador_ixc_id AS CHAR)
    WHERE DATE(COALESCE(p.data_cadastro, p.criado_em)) >= ?
      AND DATE(COALESCE(p.data_cadastro, p.criado_em)) <= ?
    ORDER BY COALESCE(p.data_cadastro, p.criado_em) DESC
    `,
    [inicio, fim]
  );

  const penalidades = penalidadesBanco.map(item => ({
    id: item.id,
    os_id: item.os_id,
    cliente: item.cliente || "-",
    contrato_id: item.contrato_id || "-",
    responsavel_id: String(item.responsavel_id || "0"),
    responsavel_nome: item.responsavel_nome || "-",
    data_cadastro: item.data_cadastro || "-",
    data_boleto: item.data_boleto || "-",
    boleto_id: item.boleto_id || "-",
    motivo: item.motivo || "-",
    observacao: item.observacao || null,
    origem: item.origem || "GESTOR",
    desconsiderada: Boolean(Number(item.desconsiderada || 0)),
    motivo_desconsideracao: item.motivo_desconsideracao || null,
    criado_por_nome: item.criado_por_nome || null,
    desconsiderado_por_nome: item.desconsiderado_por_nome || null,
    desconsiderado_em: item.desconsiderado_em || null,
    criado_em: item.criado_em || null,
    atualizado_em: item.atualizado_em || null
  }));

  const resumoPorResponsavel = {};

  penalidades.forEach(item => {
    const chave = String(item.responsavel_id || "0");

    if (!resumoPorResponsavel[chave]) {
      resumoPorResponsavel[chave] = {
        responsavel_id: item.responsavel_id,
        responsavel_nome: item.responsavel_nome,
        penalidades: 0,
        penalidades_detectadas: 0,
        penalidades_desconsideradas: 0,
        oss: []
      };
    }

    resumoPorResponsavel[chave].penalidades_detectadas += 1;
    resumoPorResponsavel[chave].oss.push(item);

    if (item.desconsiderada) {
      resumoPorResponsavel[chave].penalidades_desconsideradas += 1;
    } else {
      resumoPorResponsavel[chave].penalidades += 1;
    }
  });

        ultimaSyncPenalidadesBackoffice = new Date();

        return {
          sucesso: true,
          total_os_cadastro_finalizadas: osCadastroFinalizadas.length,
          atualizado_em: ultimaSyncPenalidadesBackoffice
        };
}

async function buscarPenalidadesBackOffice(inicio, fim) {
  const [penalidadesBanco] = await db.query(
    `
    SELECT
      p.id,
      p.os_id,
      p.colaborador_ixc_id AS responsavel_id,
      COALESCE(u.nome, u.usuario, '-') AS responsavel_nome,
      p.cliente,
      p.contrato_id,
      p.data_cadastro,
      p.data_boleto,
      p.boleto_id,
      p.motivo,
      p.observacao,
      p.origem,
      p.desconsiderada,
      p.motivo_desconsideracao,
      p.criado_por_nome,
      p.desconsiderado_por_nome,
      p.desconsiderado_em,
      p.criado_em,
      p.atualizado_em
    FROM penalidades_backoffice p
    LEFT JOIN usuarios_dashboard u
      ON CAST(u.colaborador_ixc_id AS CHAR) = CAST(p.colaborador_ixc_id AS CHAR)
    WHERE DATE(COALESCE(p.data_cadastro, p.criado_em)) >= ?
      AND DATE(COALESCE(p.data_cadastro, p.criado_em)) <= ?
    ORDER BY COALESCE(p.data_cadastro, p.criado_em) DESC
    `,
    [inicio, fim]
  );

  const penalidades = penalidadesBanco.map(item => ({
    id: item.id,
    os_id: item.os_id,
    cliente: item.cliente || "-",
    contrato_id: item.contrato_id || "-",
    responsavel_id: String(item.responsavel_id || "0"),
    responsavel_nome: item.responsavel_nome || "-",
    data_cadastro: item.data_cadastro || "-",
    data_boleto: item.data_boleto || "-",
    boleto_id: item.boleto_id || "-",
    motivo: item.motivo || "-",
    observacao: item.observacao || null,
    origem: item.origem || "GESTOR",
    desconsiderada: Boolean(Number(item.desconsiderada || 0)),
    motivo_desconsideracao: item.motivo_desconsideracao || null,
    criado_por_nome: item.criado_por_nome || null,
    desconsiderado_por_nome: item.desconsiderado_por_nome || null,
    desconsiderado_em: item.desconsiderado_em || null,
    criado_em: item.criado_em || null,
    atualizado_em: item.atualizado_em || null
  }));

  const resumoPorResponsavel = {};

  penalidades.forEach(item => {
    const chave = String(item.responsavel_id || "0");

    if (!resumoPorResponsavel[chave]) {
      resumoPorResponsavel[chave] = {
        responsavel_id: item.responsavel_id,
        responsavel_nome: item.responsavel_nome,
        penalidades: 0,
        penalidades_detectadas: 0,
        penalidades_desconsideradas: 0,
        oss: []
      };
    }

    resumoPorResponsavel[chave].penalidades_detectadas += 1;
    resumoPorResponsavel[chave].oss.push(item);

    if (item.desconsiderada) {
      resumoPorResponsavel[chave].penalidades_desconsideradas += 1;
    } else {
      resumoPorResponsavel[chave].penalidades += 1;
    }
  });

  return {
    total_penalidades_detectadas: penalidades.length,
    total_penalidades_desconsideradas: penalidades.filter(item => item.desconsiderada).length,
    total_penalidades: penalidades.filter(item => !item.desconsiderada).length,
    ultima_sincronizacao: ultimaSyncPenalidadesBackoffice,
    resumo: Object.values(resumoPorResponsavel),
    penalidades
  };
}

async function executarSyncPenalidadesBackofficeAtual() {
  if (syncPenalidadesBackofficeRodando) {
    console.log("Sync penalidades BackOffice já está em execução.");
    return;
  }

  syncPenalidadesBackofficeRodando = true;

  try {
    const hoje = new Date();
    const ano = hoje.getFullYear();
    const mes = String(hoje.getMonth() + 1).padStart(2, "0");
    const dia = String(hoje.getDate()).padStart(2, "0");

    const inicio = `${ano}-${mes}-01`;
    const fim = `${ano}-${mes}-${dia}`;

    console.time("syncPenalidadesBackOffice");

    await sincronizarPenalidadesBackOffice(inicio, fim);

    console.timeEnd("syncPenalidadesBackOffice");

  } catch (erro) {
    console.error("Erro na sync automática de penalidades BackOffice:", erro.message);
  } finally {
    syncPenalidadesBackofficeRodando = false;
  }
}

registrarDebugGet("/api/ranking-backoffice/penalidades-teste", async (req, res) => {
  try {
    const inicio = req.query.inicio;
    const fim = req.query.fim;

    if (!inicio || !fim) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe inicio e fim no formato YYYY-MM-DD."
      });
    }

    const resultado = await buscarPenalidadesBackOffice(inicio, fim);

    return res.json({
      sucesso: true,
      periodo: { inicio, fim },
      ...resultado
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

  app.get("/api/ranking-backoffice", exigirLogin, async (req, res) => {
  try {
    const dataInicial = req.query.inicio;
    const dataFinal = req.query.fim;

    if (!dataInicial || !dataFinal) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe inicio e fim no formato YYYY-MM-DD."
      });
    }

    const [backofficeRows] = await db.query(`
      SELECT usuario_id, colaborador_ixc_id, nome, ativo
      FROM colaboradores_backoffice
      WHERE ativo = 1
    `);

    const idsBackoffice = backofficeRows.map(item =>
      String(item.colaborador_ixc_id)
    );

    const mapa = {};

      backofficeRows.forEach(item => {
        mapa[String(item.colaborador_ixc_id)] = {
          colaborador_ixc_id: String(item.colaborador_ixc_id),
          nome: item.nome,
          total_cadastros: 0,
          cadastro_normal: 0,
          cadastro_fibrasil: 0,
          penalidades: 0,
          pontuacao_liquida: 0,
          itens: [],
          itens_penalidade: []
        };
      });

    const assuntosCadastro = ["2", "249"];
    let ordens = [];

    for (const idAssunto of assuntosCadastro) {
      const retornoOS = await buscar(
        "su_oss_chamado",
        "su_oss_chamado.id_assunto",
        idAssunto,
        "1000"
      );

      ordens.push(...(retornoOS.registros || []));
    }

    const ordensUnicas = new Map();

    for (const os of ordens) {
      if (os.id) {
        ordensUnicas.set(String(os.id), os);
      }
    }

    ordens = [...ordensUnicas.values()];

    for (const os of ordens) {
      const idTecnico = String(os.id_tecnico || "");
      const idAssunto = String(os.id_assunto || "");
      const setor = String(os.setor || os.id_setor || "");

      const dataFechamento = String(
        os.data_fechamento ||
        os.data_final ||
        os.ultima_atualizacao ||
        ""
      ).slice(0, 10);

      if (String(os.status) !== "F") continue;
      if (setor !== "32") continue;
      if (!idsBackoffice.includes(idTecnico)) continue;
      if (!assuntosCadastro.includes(idAssunto)) continue;
      if (dataFechamento < dataInicial || dataFechamento > dataFinal) continue;

      const registro = mapa[idTecnico];

      if (!registro) continue;

      registro.total_cadastros += 1;

      if (idAssunto === "2") {
        registro.cadastro_normal += 1;
      }

      if (idAssunto === "249") {
        registro.cadastro_fibrasil += 1;
      }

          let nomeClienteCadastro = String(os.id_cliente || "-");

          try {
            const clienteCadastro = await buscarClienteCache(os.id_cliente);

            if (clienteCadastro) {
              nomeClienteCadastro =
                clienteCadastro.razao ||
                clienteCadastro.nome ||
                nomeClienteCadastro;
            }
          } catch (erroClienteCadastro) {
            console.log(
              "Erro ao buscar cliente do cadastro:",
              os.id_cliente,
              erroClienteCadastro.message
            );
          }

          registro.itens.push({
            os_id: os.id,
            cliente_id: os.id_cliente,
            cliente_nome: nomeClienteCadastro,
            contrato_id: os.id_contrato_kit,
            assunto_id: idAssunto,
            assunto: idAssunto === "249" ? "CADASTRO - FIBRASIL" : "CADASTRO",
            data_fechamento: dataFechamento,
            status: os.status
          });
    }

    const penalidadesBackoffice = await buscarPenalidadesBackOffice(dataInicial, dataFinal);

      penalidadesBackoffice.resumo.forEach(item => {
        const idResponsavel = String(item.responsavel_id || "");

        if (!mapa[idResponsavel]) return;

        mapa[idResponsavel].penalidades = Number(item.penalidades || 0);
        mapa[idResponsavel].itens_penalidade = item.oss || [];
      });

      Object.values(mapa).forEach(item => {
        item.pontuacao_liquida =
          Number(item.total_cadastros || 0) -
          Number(item.penalidades || 0);
      });

      const ranking = Object.values(mapa)
        .sort((a, b) => {
          if (b.pontuacao_liquida !== a.pontuacao_liquida) {
            return b.pontuacao_liquida - a.pontuacao_liquida;
          }

          return b.total_cadastros - a.total_cadastros;
        })
        .map((item, index) => ({
          ...item,
          posicao: index + 1
        }));

    res.json({
      periodo: {
        inicio: dataInicial,
        fim: dataFinal
      },
      total_cadastros: ranking.reduce((soma, item) => soma + item.total_cadastros, 0),
      total_cadastro_normal: ranking.reduce((soma, item) => soma + item.cadastro_normal, 0),
      total_cadastro_fibrasil: ranking.reduce((soma, item) => soma + item.cadastro_fibrasil, 0),
      total_penalidades: ranking.reduce((soma, item) => soma + Number(item.penalidades || 0), 0),
      total_pontuacao_liquida: ranking.reduce((soma, item) => soma + Number(item.pontuacao_liquida || 0), 0),
      ranking,
      cache: false
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      status: erro.response?.status || null,
      mensagem: erro.response?.data || erro.message
    });
  }
});


app.get("/api/metas-vendedores", exigirLogin, exigirPermissao("gerenciar_metas"), async (req, res) => {
  try {
    const mes = req.query.mes;

    if (!mes) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe o mês no formato YYYY-MM."
      });
    }

    const usuarioLogado = req.session.usuario;

    if (!podeGerenciarMetas(usuarioLogado)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso negado."
      });
    }

    const [existentes] = await db.query(
      "SELECT COUNT(*) AS total FROM metas_vendedores WHERE mes = ?",
      [mes]
    );

    if (Number(existentes[0]?.total || 0) === 0) {
      await db.query(
        `
        INSERT INTO metas_vendedores (vendedor_id, vendedor_nome, mes, meta, ativo)
        SELECT vendedor_id, nome, ?, 0, 1
        FROM usuarios_dashboard
        WHERE perfil = 'vendedor'
          AND ativo = 1
          AND vendedor_id IS NOT NULL
          AND vendedor_id <> ''
        `,
        [mes]
      );
    }

    const [metas] = await db.query(
      `
      SELECT vendedor_id, vendedor_nome, mes, meta, ativo
      FROM metas_vendedores
      WHERE mes = ?
      ORDER BY vendedor_nome
      `,
      [mes]
    );

    res.json({ mes, metas });

  } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao salvar meta de vendedor"
      );
  }
});

app.post("/api/metas-vendedores", exigirLogin, exigirPermissao("gerenciar_metas"), async (req, res) => {
  try {
    const usuarioLogado = req.session.usuario;

    if (!podeGerenciarMetas(usuarioLogado)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso negado."
      });
    }

    const { vendedor_id, vendedor_nome, mes, meta } = req.body;

    await db.query(
      `
      INSERT INTO metas_vendedores (vendedor_id, vendedor_nome, mes, meta)
      VALUES (?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        vendedor_nome = VALUES(vendedor_nome),
        meta = VALUES(meta),
        ativo = 1
      `,
      [vendedor_id, vendedor_nome, mes, Number(meta || 0)]
    );

        for (const chave of Object.keys(cacheRankingReceita)) {
          if (chave.includes(mes)) {
            delete cacheRankingReceita[chave];
          }
        }

    res.json({
      sucesso: true,
      mensagem: "Meta atualizada com sucesso."
    });

  } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao remover meta de vendedor"
      );
  }
});

app.delete("/api/metas-vendedores/:vendedorId/:mes", exigirLogin, exigirPermissao("gerenciar_metas"), async (req, res) => {
  try {
    const usuarioLogado = req.session.usuario;

    if (!podeGerenciarMetas(usuarioLogado)) {
      return  res.status(403).json({
        erro: true,
        mensagem: "Acesso negado."
      });
    }

    await db.query(
      "DELETE FROM metas_vendedores WHERE vendedor_id = ? AND mes = ?",
      [req.params.vendedorId, req.params.mes]
    );

    res.json({
      sucesso: true,
      mensagem: "Vendedor removido das metas."
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

app.patch("/api/metas-vendedores/:vendedorId/:mes/status", exigirLogin, exigirPermissao("gerenciar_metas"), async (req, res) => {
  try {
    const usuarioLogado = req.session.usuario;

    if (!podeGerenciarMetas(usuarioLogado)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso negado."
      });
    }

    const { ativo } = req.body;

    await db.query(
      "UPDATE metas_vendedores SET ativo = ? WHERE vendedor_id = ? AND mes = ?",
      [Boolean(ativo) ? 1 : 0, req.params.vendedorId, req.params.mes]
    );

    res.json({
      sucesso: true,
      mensagem: "Status da meta atualizado."
    });

  } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao alterar status da meta"
      );
  }
});


// =========================================================
// API LINK DEDICADO
// =========================================================

const NATUREZAS_LINK_DEDICADO = {
  atacado: ["4", "39", "41"],
  corporativo: ["5", "37", "35"]
};

const cacheCidadesIXC = {};

let cacheLinkDedicado = null;
let cacheLinkDedicadoCriadoEm = 0;
const TEMPO_CACHE_LINK_DEDICADO = 30 * 60 * 1000;


async function buscarCidadeIXCCache(cidadeId) {
  if (!cidadeId || cidadeId === "0" || cidadeId === "-") return "-";

  const chave = String(cidadeId);

  if (cacheCidadesIXC[chave]) {
    return cacheCidadesIXC[chave];
  }

  try {
    const retorno = await buscar("cidade", "cidade.id", chave, "1");
    const cidade = retorno.registros?.[0];

    const nomeCidade =
      cidade?.nome ||
      cidade?.cidade ||
      cidade?.descricao ||
      `Cidade ${chave}`;

    cacheCidadesIXC[chave] = nomeCidade;

    return nomeCidade;
  } catch (erro) {
    cacheCidadesIXC[chave] = `Cidade ${chave}`;
    return cacheCidadesIXC[chave];
  }
}

function podeAcessarLinkDedicadoBackend(usuario) {
  const permissoes = usuario?.permissoes || [];

  return (
    usuario?.perfil === "super_admin" ||
    usuario?.perfil === "gerencial" ||
    permissoes.includes("ver_link_dedicado")
  );
}

function tipoLinkDedicadoPorNatureza(idNatureza) {
  const id = String(idNatureza || "");

  if (NATUREZAS_LINK_DEDICADO.atacado.includes(id)) {
    return "ATACADO";
  }

  if (NATUREZAS_LINK_DEDICADO.corporativo.includes(id)) {
    return "CORPORATIVO";
  }

  return null;
}

function obterDataVencimentoLink(contrato) {
  const datasPossiveis = [
    contrato.data_renovacao,
    contrato.data_validade,
    contrato.data_final,
    contrato.data_vencimento,
    contrato.data_expiracao
  ];

  const data = datasPossiveis.find(item =>
    item &&
    item !== "0000-00-00" &&
    item !== "0000-00-00 00:00:00"
  );

  return data ? String(data).slice(0, 10) : null;
}

function calcularDiasParaVencer(dataVencimento) {
  if (!dataVencimento) return null;

  const hoje = new Date();
  hoje.setHours(0, 0, 0, 0);

  const vencimento = new Date(`${dataVencimento}T00:00:00`);

  if (isNaN(vencimento.getTime())) return null;

  const diffMs = vencimento.getTime() - hoje.getTime();

  return Math.ceil(diffMs / (1000 * 60 * 60 * 24));
}

function faixaVencimentoLink(dias) {
  if (dias === null || dias === undefined) return "sem_data";
  if (dias < 0) return "vencido";
  if (dias <= 30) return "vencem_30";
  if (dias <= 60) return "vencem_60";
  if (dias <= 90) return "vencem_90";
  return "acima_90";
}

async function buscarContratosLinkDedicado() {
  const TIPOS_CLIENTE_LINK = ["39", "41", "5", "35", "37"];

  const clientesMap = new Map();

  for (const tipoClienteId of TIPOS_CLIENTE_LINK) {
    const retornoClientes = await buscar(
      "cliente",
      "cliente.id_tipo_cliente",
      tipoClienteId,
      "1000"
    );

    for (const cliente of retornoClientes.registros || []) {
      if (!cliente.id) continue;
      clientesMap.set(String(cliente.id), cliente);
      salvarCache("clientes", String(cliente.id), cliente);
    }
  }

  const contratosMap = new Map();

  for (const cliente of clientesMap.values()) {
    const retornoContratos = await buscar(
      "cliente_contrato",
      "cliente_contrato.id_cliente",
      String(cliente.id),
      "100"
    );

    for (const contrato of retornoContratos.registros || []) {
      if (!contrato.id) continue;
      if (String(contrato.status) !== "A") continue;

      contrato._cliente_link = cliente;
      contratosMap.set(String(contrato.id), contrato);
    }
  }

  return [...contratosMap.values()];
}

async function montarLinkDedicado() {
  const [colaboradoresRows] = await db.query(`
    SELECT vendedor_ixc_id, nome, ativo_empresa, ativo_rastreamento
    FROM colaboradores_link_dedicado
    WHERE ativo_rastreamento = 1
  `);

  const mapaColaboradores = {};
  colaboradoresRows.forEach(item => {
    mapaColaboradores[String(item.vendedor_ixc_id)] = item;
  });

  const contratos = await buscarContratosLinkDedicado();

  const resultado = [];

  for (const contrato of contratos) {

        const vendedorId = String(contrato.id_vendedor || "");
        const vendedorMapeado = mapaColaboradores[vendedorId];

        const vendedorNome =
          vendedorMapeado?.nome ||
          contrato.vendedor ||
          `Não mapeado (${vendedorId || "sem ID"})`;

      const cliente = contrato._cliente_link || await buscarClienteCache(contrato.id_cliente);


      const plano = contrato.id_vd_contrato
        ? await buscar("vd_contratos", "id", contrato.id_vd_contrato, "1")
        : { registros: [] };

      const cidadeId = cliente?.cidade || contrato.cidade || null;
      const cidadeNome = await buscarCidadeIXCCache(cidadeId);

        const tipo = classificarTipoClienteLinkDedicado(cliente, contrato._link_oficial);

        if (!tipo) continue;

        const motivosInclusaoValidos = ["1", "8"];

        if (!motivosInclusaoValidos.includes(String(contrato.id_motivo_inclusao || ""))) {
          continue;
        }

    const planoEncontrado = plano.registros?.[0] || null;

      const valorMensal = numeroIXC(
        contrato.valor_contrato ||
        contrato.valor ||
        planoEncontrado?.valor_contrato
      );

    const dataVencimento = obterDataVencimentoLink(contrato);
    const diasParaVencer = calcularDiasParaVencer(dataVencimento);


    resultado.push({
      contrato_id: contrato.id,
      cliente_id: contrato.id_cliente,
      cliente: cliente?.razao || cliente?.nome || cliente?.fantasia || `Cliente ID ${contrato.id_cliente}`,
      vendedor_id: vendedorId,
      vendedor: vendedorNome,
      vendedor_ativo_empresa: Boolean(Number(mapaColaboradores[vendedorId]?.ativo_empresa || 0)),
      tipo,
      id_tipo_cliente: cliente?.id_tipo_cliente || null,
      id_carteira_cobranca: contrato.id_carteira_cobranca || null,
      natureza_id: "",
      plano_id: contrato.id_vd_contrato || "",
      plano: planoEncontrado?.nome || contrato.contrato || contrato.descricao_aux_plano_venda || "-",
      valor_mensal: valorMensal,
      cidade: cidadeNome,
      cidade_id: cidadeId,
      bairro: cliente?.bairro || contrato.bairro || "-",
      latitude: cliente?.latitude || null,
      longitude: cliente?.longitude || null,
      status: contrato.status || "-",
      status_internet: contrato.status_internet || "-",
      situacao: classificarSituacaoContrato(contrato),
      data_inicio: contrato.data || contrato.data_ativacao || null,
      data_ativacao: contrato.data_ativacao || null,
      data_renovacao: contrato.data_renovacao || null,
      data_vencimento: dataVencimento,
      dias_para_vencer: diasParaVencer,
      faixa_vencimento: faixaVencimentoLink(diasParaVencer)
    });
  }

  const ativos = resultado.filter(item =>
    item.situacao === "ATIVO"
  );

  const receitaMensal = ativos.reduce(
    (soma, item) => soma + Number(item.valor_mensal || 0),
    0
  );

  return {
    total_links: ativos.length,
    total_atacado: ativos.filter(item => item.tipo === "ATACADO").length,
    total_corporativo: ativos.filter(item => item.tipo === "CORPORATIVO").length,
    receita_mensal: Number(receitaMensal.toFixed(2)),

    vencidos: ativos.filter(item => item.faixa_vencimento === "vencido").length,
    vencem_30: ativos.filter(item => item.faixa_vencimento === "vencem_30").length,
    vencem_60: ativos.filter(item => item.faixa_vencimento === "vencem_60").length,
    vencem_90: ativos.filter(item => item.faixa_vencimento === "vencem_90").length,

    contratos: ativos,
    debug: {
      contratos_ixc_encontrados: contratos.length,
      contratos_link_filtrados: resultado.length,
      colaboradores_rastreamento: colaboradoresRows.length,
      fonte_classificacao: "planos_link_dedicado"
    },
    atualizado_em: new Date().toLocaleString("pt-BR")
  };
}

async function montarLinkDedicadoBanco() {

  const [rows] = await db.query(`
    SELECT *
    FROM link_dedicado_contratos
  `);

  const contratos = rows.map(item => ({
    ...item,
    valor_contratado: Number(item.valor_contratado || 0)
  }));

  const ativos = contratos.filter(item =>
    item.status === "A"
  );

  const receita = ativos.reduce(
    (soma, item) => soma + item.valor_contratado,
    0
  );


function agruparLink(lista, campo) {
  const mapa = {};

  lista.forEach(item => {
    const chave = item[campo] || "Não informado";

    if (!mapa[chave]) {
      mapa[chave] = {
        nome: chave,
        total: 0,
        receita: 0,
        atacado: 0,
        corporativo: 0,
        outros: 0,
        vencidos: 0,
        vencem_30: 0,
        vencem_60: 0,
        vencem_90: 0,
        acima_90: 0,
        sem_data: 0
      };
    }

    mapa[chave].total += 1;
    mapa[chave].receita += Number(item.valor_contratado || 0);

    if (item.tipo === "ATACADO") mapa[chave].atacado += 1;
    if (item.tipo === "CORPORATIVO") mapa[chave].corporativo += 1;
    if (item.tipo === "OUTROS") mapa[chave].outros += 1;

    if (item.faixa_vencimento === "vencido") mapa[chave].vencidos += 1;
    if (item.faixa_vencimento === "vencem_30") mapa[chave].vencem_30 += 1;
    if (item.faixa_vencimento === "vencem_60") mapa[chave].vencem_60 += 1;
    if (item.faixa_vencimento === "vencem_90") mapa[chave].vencem_90 += 1;
    if (item.faixa_vencimento === "acima_90") mapa[chave].acima_90 += 1;
    if (item.faixa_vencimento === "sem_data") mapa[chave].sem_data += 1;
  });

  return Object.values(mapa)
    .map(item => ({
      ...item,
      receita: Number(item.receita.toFixed(2))
    }))
    .sort((a, b) => b.receita - a.receita);
}

const ticketMedio = ativos.length
  ? receita / ativos.length
  : 0;

const contratosOrdenadosValor = [...ativos].sort(
  (a, b) => Number(b.valor_contratado || 0) - Number(a.valor_contratado || 0)
);

const contratosVencimentoCritico = [...ativos]
  .filter(c =>
    ["vencido", "vencem_30", "vencem_60", "vencem_90"].includes(c.faixa_vencimento)
  )
  .sort((a, b) => Number(a.dias_para_vencer ?? 9999) - Number(b.dias_para_vencer ?? 9999));

const maiorContrato = contratosOrdenadosValor[0] || null;
const proximaRenovacao = contratosVencimentoCritico[0] || null;

const receitaAtacado = ativos
  .filter(c => c.tipo === "ATACADO")
  .reduce((soma, c) => soma + Number(c.valor_contratado || 0), 0);

const receitaCorporativo = ativos
  .filter(c => c.tipo === "CORPORATIVO")
  .reduce((soma, c) => soma + Number(c.valor_contratado || 0), 0);

const receitaOutros = ativos
  .filter(c => c.tipo === "OUTROS")
  .reduce((soma, c) => soma + Number(c.valor_contratado || 0), 0);


  return {

    total_links: ativos.length,

    total_atacado: ativos.filter(c => c.tipo === "ATACADO").length,

    total_corporativo: ativos.filter(c => c.tipo === "CORPORATIVO").length,

    total_outros: ativos.filter(c => c.tipo === "OUTROS").length,

    receita_mensal: Number(receita.toFixed(2)),

    vencidos: ativos.filter(c => c.faixa_vencimento === "vencido").length,

    vencem_30: ativos.filter(c => c.faixa_vencimento === "vencem_30").length,

    vencem_60: ativos.filter(c => c.faixa_vencimento === "vencem_60").length,

    vencem_90: ativos.filter(c => c.faixa_vencimento === "vencem_90").length,

    dashboard_executivo: {
        receita_total: Number(receita.toFixed(2)),
        total_contratos: ativos.length,

        ticket_medio: Number(ticketMedio.toFixed(2)),

        atacado: {
          total: ativos.filter(c => c.tipo === "ATACADO").length,
          receita: Number(receitaAtacado.toFixed(2))
        },

        corporativo: {
          total: ativos.filter(c => c.tipo === "CORPORATIVO").length,
          receita: Number(receitaCorporativo.toFixed(2))
        },

        outros: {
          total: ativos.filter(c => c.tipo === "OUTROS").length,
          receita: Number(receitaOutros.toFixed(2))
        },

        maior_contrato: maiorContrato
          ? {
              contrato_ixc_id: maiorContrato.contrato_ixc_id,
              cliente: maiorContrato.cliente,
              cidade: maiorContrato.cidade,
              vendedor: maiorContrato.vendedor,
              tipo: maiorContrato.tipo,
              plano: maiorContrato.plano,
              valor_contratado: Number(maiorContrato.valor_contratado || 0)
            }
          : null,

        proxima_renovacao: proximaRenovacao
          ? {
              contrato_ixc_id: proximaRenovacao.contrato_ixc_id,
              cliente: proximaRenovacao.cliente,
              cidade: proximaRenovacao.cidade,
              vendedor: proximaRenovacao.vendedor,
              tipo: proximaRenovacao.tipo,
              plano: proximaRenovacao.plano,
              valor_contratado: Number(proximaRenovacao.valor_contratado || 0),
              data_vencimento: proximaRenovacao.data_vencimento,
              dias_para_vencer: proximaRenovacao.dias_para_vencer,
              faixa_vencimento: proximaRenovacao.faixa_vencimento
            }
          : null,

        top_contratos: contratosOrdenadosValor.slice(0, 10).map(c => ({
          contrato_ixc_id: c.contrato_ixc_id,
          cliente: c.cliente,
          cidade: c.cidade,
          vendedor: c.vendedor,
          tipo: c.tipo,
          plano: c.plano,
          valor_contratado: Number(c.valor_contratado || 0)
        }))
      },

    contratos: ativos,

    resumo_por_tipo: agruparLink(ativos, "tipo"),
    resumo_por_vendedor: agruparLink(ativos, "vendedor"),
    resumo_por_cidade: agruparLink(ativos, "cidade"),

    atualizado_em: new Date().toLocaleString("pt-BR")
  };

}

registrarDebugGet("/api/debug-link-dedicado-campos/:contratoId", async (req, res) => {
  try {
    const contratoId = req.params.contratoId;

    const retorno = await buscar(
      "cliente_contrato",
      "cliente_contrato.id",
      contratoId,
      "1"
    );

    const contrato = retorno.registros?.[0] || null;

    res.json({
      contrato_id: contratoId,
      contrato
    });
  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});

app.get("/api/link-dedicado", exigirLogin, async (req, res) => {
  try {
    const usuarioLogado = req.session.usuario;

    if (!podeAcessarLinkDedicadoBackend(usuarioLogado)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso negado ao módulo Link Dedicado."
      });
    }

    const agora = Date.now();
    const cacheValido =
      cacheLinkDedicado &&
      agora - cacheLinkDedicadoCriadoEm < TEMPO_CACHE_LINK_DEDICADO;

    if (cacheValido) {
      return res.json({
        ...cacheLinkDedicado,
        cache: true
      });
    }


    const [ultimaSyncRows] = await db.query(`
        SELECT MAX(ultima_sincronizacao) AS ultima
        FROM link_dedicado_contratos
      `);

      const ultimaSync = ultimaSyncRows[0]?.ultima;
      const baseVaziaOuVencida =
        !ultimaSync ||
        Date.now() - new Date(ultimaSync).getTime() > TEMPO_CACHE_LINK_DEDICADO;

      let sincronizouAgora = false;

      if (baseVaziaOuVencida) {
        await sincronizarLinkDedicadoBanco();
        sincronizouAgora = true;
      }

    const dados = await montarLinkDedicadoBanco();

    cacheLinkDedicado = JSON.parse(JSON.stringify(dados));
    cacheLinkDedicadoCriadoEm = agora;

    return res.json({
      ...dados,
      cache: false,
      sincronizou_agora: sincronizouAgora
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      status: erro.response?.status || null,
      mensagem: erro.response?.data || erro.message
    });
  }
});

registrarDebugGet("/api/debug-link-dedicado-contrato/:vendedorId", async (req, res) => {
  try {
    const vendedorId = req.params.vendedorId;

    const retorno = await buscar(
      "cliente_contrato",
      "cliente_contrato.id_vendedor",
      vendedorId,
      "5"
    );

    res.json({
      vendedor_id: vendedorId,
      total: retorno.registros?.length || 0,
      contratos: retorno.registros || []
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});

registrarDebugGet("/api/debug-link-dedicado-planos", async (req, res) => {
  try {
    const [colaboradores] = await db.query(`
      SELECT vendedor_ixc_id, nome
      FROM colaboradores_link_dedicado
      WHERE ativo_rastreamento = 1
    `);

    const mapaPlanos = new Map();

    for (const colaborador of colaboradores) {
      const retorno = await buscar(
        "cliente_contrato",
        "cliente_contrato.id_vendedor",
        String(colaborador.vendedor_ixc_id),
        "1000"
      );

      for (const contrato of retorno.registros || []) {
        const planoId = String(contrato.id_vd_contrato || "");
        if (!planoId || planoId === "0") continue;

        if (!mapaPlanos.has(planoId)) {
          mapaPlanos.set(planoId, {
            id_vd_contrato: planoId,
            id_modelo: contrato.id_modelo || null,
            nome: contrato.contrato || contrato.descricao_aux_plano_venda || "-",
            exemplos: [],
            total_contratos: 0
          });
        }

        const item = mapaPlanos.get(planoId);
        item.total_contratos += 1;

        if (item.exemplos.length < 3) {
          item.exemplos.push({
            contrato_id: contrato.id,
            cliente_id: contrato.id_cliente,
            vendedor_id: contrato.id_vendedor,
            status: contrato.status,
            status_internet: contrato.status_internet
          });
        }
      }
    }

    const planos = [...mapaPlanos.values()]
      .sort((a, b) => Number(b.total_contratos) - Number(a.total_contratos));

    res.json({
      total_planos: planos.length,
      planos
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});

function classificarTipoClienteLinkDedicado(cliente) {
  const idTipoCliente = String(cliente?.id_tipo_cliente || "");

  if (["41", "39"].includes(idTipoCliente)) {
    return "ATACADO";
  }

  if (["5", "37", "35"].includes(idTipoCliente)) {
    return "CORPORATIVO";
  }

  return null;
}

function classificarPlanoLinkDedicado(nomePlano) {
  const nome = String(nomePlano || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toUpperCase()
    .trim();

  const ehLink =
    nome.includes("DEDICADO") ||
    nome.includes("DEDICATED") ||
    nome.includes("CORPORATE XPRESS") ||
    nome.includes("ENTERPRISE XPRESS") ||
    nome.includes("EILD");

  if (!ehLink) return null;

  if (
    nome.includes("EILD") ||
    nome.includes("REDE NEUTRA")
  ) {
    return "ATACADO";
  }

  return "CORPORATIVO";
}

app.post("/api/sync/planos-link-dedicado", exigirLogin, exigirPermissao("sincronizar_dados"), async (req, res) => {
  try {
    const usuarioLogado = req.session.usuario;

    if (!podeAcessarLinkDedicadoBackend(usuarioLogado)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso negado ao módulo Link Dedicado."
      });
    }

    const [colaboradores] = await db.query(`
      SELECT vendedor_ixc_id, nome
      FROM colaboradores_link_dedicado
      WHERE ativo_rastreamento = 1
    `);

    const mapaPlanos = new Map();

    for (const colaborador of colaboradores) {
      const retorno = await buscar(
        "cliente_contrato",
        "cliente_contrato.id_vendedor",
        String(colaborador.vendedor_ixc_id),
        "1000"
      );

      for (const contrato of retorno.registros || []) {
        const planoId = String(contrato.id_vd_contrato || "");
        if (!planoId || planoId === "0") continue;

        const nomePlano =
          contrato.contrato ||
          contrato.descricao_aux_plano_venda ||
          "-";

        const tipo = classificarPlanoLinkDedicado(nomePlano);

        if (!tipo) continue;

        if (!mapaPlanos.has(planoId)) {
          mapaPlanos.set(planoId, {
            id_vd_contrato: Number(planoId),
            id_modelo: contrato.id_modelo ? Number(contrato.id_modelo) : null,
            nome: nomePlano,
            tipo,
            total_contratos_encontrados: 0,
            exemplos: []
          });
        }

        const item = mapaPlanos.get(planoId);

        item.total_contratos_encontrados += 1;

        if (item.exemplos.length < 3) {
          item.exemplos.push({
            contrato_id: contrato.id,
            cliente_id: contrato.id_cliente,
            vendedor_id: contrato.id_vendedor,
            status: contrato.status,
            status_internet: contrato.status_internet
          });
        }
      }
    }

    const planos = [...mapaPlanos.values()]
      .sort((a, b) => a.nome.localeCompare(b.nome));

    let inseridosOuAtualizados = 0;

    for (const plano of planos) {
      await db.query(
        `
        INSERT INTO planos_link_dedicado
          (id_vd_contrato, id_modelo, nome, tipo, ativo, observacao)
        VALUES
          (?, ?, ?, ?, 1, ?)
        ON DUPLICATE KEY UPDATE
          id_modelo = VALUES(id_modelo),
          nome = VALUES(nome),
          tipo = VALUES(tipo),
          ativo = 1,
          observacao = VALUES(observacao)
        `,
        [
          plano.id_vd_contrato,
          plano.id_modelo,
          plano.nome,
          plano.tipo,
          `Importado automaticamente. Contratos encontrados: ${plano.total_contratos_encontrados}`
        ]
      );

      inseridosOuAtualizados += 1;
    }

    cacheLinkDedicado = null;
    cacheLinkDedicadoCriadoEm = 0;

    return res.json({
      sucesso: true,
      mensagem: "Planos de Link Dedicado sincronizados com sucesso.",
      total_planos_detectados: planos.length,
      total_gravados: inseridosOuAtualizados,
      planos
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      status: erro.response?.status || null,
      mensagem: erro.response?.data || erro.message
    });
  }
});


function normalizarDataMysql(data) {
  if (!data) return null;

  const valor = String(data).slice(0, 10);

  if (
    valor === "0000-00-00" ||
    valor === "0000-00-00 00:00:00" ||
    valor === ""
  ) {
    return null;
  }

  return valor;
}

async function sincronizarLinkDedicadoBanco() {
  const dados = await montarLinkDedicado();
  const contratos = dados.contratos || [];
  const sincronizadoEm = new Date();

  let gravados = 0;

  for (const item of contratos) {
    await db.query(
      `
      INSERT INTO link_dedicado_contratos (
        contrato_ixc_id,
        cliente_ixc_id,
        cliente,
        empresa,
        cidade,
        cidade_id,
        bairro,
        latitude,
        longitude,
        vendedor_ixc_id,
        vendedor,
        tipo,
        id_carteira_cobranca,
        id_tipo_cliente,
        plano_ixc_id,
        plano,
        valor_contratado,
        status,
        status_internet,
        data_inicio,
        data_ativacao,
        data_vencimento,
        dias_para_vencer,
        faixa_vencimento,
        sincronizado_em,
        ultima_sincronizacao
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        cliente = VALUES(cliente),
        empresa = VALUES(empresa),
        cidade = VALUES(cidade),
        cidade_id = VALUES(cidade_id),
        bairro = VALUES(bairro),
        latitude = VALUES(latitude),
        longitude = VALUES(longitude),
        vendedor_ixc_id = VALUES(vendedor_ixc_id),
        vendedor = VALUES(vendedor),
        tipo = VALUES(tipo),
        id_carteira_cobranca = VALUES(id_carteira_cobranca),
        id_tipo_cliente = VALUES(id_tipo_cliente),
        plano_ixc_id = VALUES(plano_ixc_id),
        plano = VALUES(plano),
        valor_contratado = VALUES(valor_contratado),
        status = VALUES(status),
        status_internet = VALUES(status_internet),
        data_inicio = VALUES(data_inicio),
        data_ativacao = VALUES(data_ativacao),
        data_vencimento = VALUES(data_vencimento),
        dias_para_vencer = VALUES(dias_para_vencer),
        faixa_vencimento = VALUES(faixa_vencimento),
        sincronizado_em = VALUES(sincronizado_em),
        ultima_sincronizacao = VALUES(ultima_sincronizacao)
      `,
      [
        item.contrato_id,
        item.cliente_id,
        item.cliente,
        item.cliente,
        item.cidade,
        item.cidade_id || null,
        item.bairro,
        item.latitude || null,
        item.longitude || null,
        item.vendedor_id,
        item.vendedor,
        item.tipo,
        item.id_carteira_cobranca || null,
        item.id_tipo_cliente || null,
        item.plano_id,
        item.plano,
        item.valor_mensal || 0,
        item.status,
        item.status_internet,
        normalizarDataMysql(item.data_inicio),
        normalizarDataMysql(item.data_ativacao),
        normalizarDataMysql(item.data_vencimento),
        item.dias_para_vencer,
        item.faixa_vencimento,
        sincronizadoEm,
        sincronizadoEm
      ]
    );

    gravados++;
  }

  cacheLinkDedicado = null;
  cacheLinkDedicadoCriadoEm = 0;

  return {
    total_encontrados: contratos.length,
    total_gravados: gravados,
    sincronizado_em: sincronizadoEm
  };
}


app.post("/api/sync/link-dedicado", exigirLogin, exigirPermissao("sincronizar_dados"), async (req, res) => {
  try {
    const usuarioLogado = req.session.usuario;

    if (!podeAcessarLinkDedicadoBackend(usuarioLogado)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso negado ao módulo Link Dedicado."
      });
    }

    const dados = await montarLinkDedicado();
    const contratos = dados.contratos || [];
    const sincronizadoEm = new Date();

    let gravados = 0;

      const resultado = await sincronizarLinkDedicadoBanco();

      return res.json({
        sucesso: true,
        mensagem: "Contratos de Link Dedicado sincronizados com sucesso.",
        total_encontrados: resultado.total_encontrados,
        total_gravados: resultado.total_gravados,
        atualizado_em: new Date().toLocaleString("pt-BR")
      });

  } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao sincronizar Link Dedicado"
      );
  }
});

registrarDebugGet("/api/debug-link-dedicado-financeiro", async (req, res) => {
  try {
    const dados = await montarLinkDedicado();

    const contratos = dados.contratos || [];

    const topValores = contratos
      .map(item => ({
        contrato_id: item.contrato_id,
        cliente: item.cliente,
        vendedor: item.vendedor,
        tipo: item.tipo,
        plano: item.plano,
        valor_mensal: item.valor_mensal,
        status: item.status,
        status_internet: item.status_internet,
        data_vencimento: item.data_vencimento,
        dias_para_vencer: item.dias_para_vencer
      }))
      .sort((a, b) => Number(b.valor_mensal || 0) - Number(a.valor_mensal || 0))
      .slice(0, 30);

    res.json({
      total_contratos: contratos.length,
      receita_mensal_calculada: dados.receita_mensal,
      top_30_maiores_valores: topValores
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

registrarDebugGet(
  "/api/debug/motivos-cancelamento",
  async (req, res) => {
    try {
      const retorno = await buscar(
        "motivo_cancelamento",
        "motivo_cancelamento.id",
        "0",
        "1000"
      );

      const registros =
        retorno.registros || [];

      return res.json({
        sucesso: true,
        endpoint: "motivo_cancelamento",
        total: registros.length,
        campos:
          registros.length
            ? Object.keys(registros[0]).sort()
            : [],
        motivos: registros
      });

    } catch (erro) {
      return res.status(500).json({
        erro: true,
        endpoint_testado:
          "motivo_cancelamento",
        mensagem:
          erro.response?.data ||
          erro.message
      });
    }
  }
);

registrarDebugGet(
  "/api/debug/descobrir-motivos-cancelamento",
  async (req, res) => {
    const motivoId =
      String(req.query.id || "269");

    const candidatos = [
      {
        endpoint: "motivo_cancelamento",
        qtypes: [
          "motivo_cancelamento.id",
          "id"
        ]
      },
      {
        endpoint:
          "cliente_contrato_motivo_cancelamento",
        qtypes: [
          "cliente_contrato_motivo_cancelamento.id",
          "id"
        ]
      },
      {
        endpoint: "motivos_cancelamento",
        qtypes: [
          "motivos_cancelamento.id",
          "id"
        ]
      },
      {
        endpoint: "tipo_cancelamento",
        qtypes: [
          "tipo_cancelamento.id",
          "id"
        ]
      },
      {
        endpoint: "cancelamento_motivo",
        qtypes: [
          "cancelamento_motivo.id",
          "id"
        ]
      }
    ];

    const resultados = [];

    for (const candidato of candidatos) {
      for (const qtype of candidato.qtypes) {
        try {
          const retorno = await buscar(
            candidato.endpoint,
            qtype,
            motivoId,
            "10"
          );

          const registros =
            retorno.registros || [];

          resultados.push({
            endpoint:
              candidato.endpoint,

            qtype,

            motivo_id_testado:
              motivoId,

            sucesso_requisicao:
              true,

            total:
              registros.length,

            total_ixc:
              retorno.total || null,

            campos:
              registros.length
                ? Object.keys(
                    registros[0]
                  ).sort()
                : [],

            registros
          });

        } catch (erro) {
          resultados.push({
            endpoint:
              candidato.endpoint,

            qtype,

            motivo_id_testado:
              motivoId,

            sucesso_requisicao:
              false,

            status:
              erro.response?.status ||
              null,

            mensagem:
              erro.response?.data ||
              erro.message
          });
        }
      }
    }

    return res.json({
      sucesso: true,
      motivo_id_testado:
        motivoId,
      resultados
    });
  }
);

registrarDebugGet(
  "/api/debug/mapear-motivos-cancelamento",
  async (req, res) => {
    try {
      const inicio =
        String(req.query.inicio || "");

      const fim =
        String(req.query.fim || "");

      if (
        !/^\d{4}-\d{2}-\d{2}$/.test(inicio) ||
        !/^\d{4}-\d{2}-\d{2}$/.test(fim)
      ) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "Informe inicio e fim no formato YYYY-MM-DD."
        });
      }

      const datas =
        gerarDatasPeriodo(inicio, fim);

      const contratosMap =
        new Map();

      for (const data of datas) {
        const retorno =
          await buscar(
            "cliente_contrato",
            "cliente_contrato.data_cancelamento",
            data,
            "1000"
          );

        for (
          const contrato
          of retorno.registros || []
        ) {
          if (!contrato.id) continue;

          contratosMap.set(
            String(contrato.id),
            contrato
          );
        }
      }

      const mapaMotivos =
        new Map();

      for (
        const contrato
        of contratosMap.values()
      ) {
        const motivoId =
          String(
            contrato.motivo_cancelamento ||
            "0"
          );

        if (
          !motivoId ||
          motivoId === "0"
        ) {
          continue;
        }

        if (!mapaMotivos.has(motivoId)) {
          mapaMotivos.set(motivoId, {
            motivo_id: motivoId,
            total: 0,
            observacoes: new Map(),
            exemplos: []
          });
        }

        const item =
          mapaMotivos.get(motivoId);

        item.total += 1;

        const observacao =
          String(
            contrato.obs_cancelamento ||
            ""
          ).trim();

        if (observacao) {
          item.observacoes.set(
            observacao,
            (
              item.observacoes.get(
                observacao
              ) || 0
            ) + 1
          );
        }

        if (item.exemplos.length < 5) {
          item.exemplos.push({
            contrato_id:
              String(contrato.id),

            cliente_id:
              String(
                contrato.id_cliente || ""
              ),

            data_ativacao:
              contrato.data_ativacao ||
              null,

            data_cancelamento:
              contrato.data_cancelamento ||
              null,

            observacao:
              observacao || null
          });
        }
      }

      const motivos =
        [...mapaMotivos.values()]
          .map(item => ({
            motivo_id:
              item.motivo_id,

            total:
              item.total,

            observacoes:
              [...item.observacoes.entries()]
                .map(
                  ([texto, quantidade]) => ({
                    texto,
                    quantidade
                  })
                )
                .sort(
                  (a, b) =>
                    b.quantidade -
                    a.quantidade
                )
                .slice(0, 20),

            exemplos:
              item.exemplos
          }))
          .sort(
            (a, b) =>
              b.total - a.total
          );

      return res.json({
        sucesso: true,
        periodo: {
          inicio,
          fim
        },
        total_contratos_cancelados:
          contratosMap.size,
        total_motivos:
          motivos.length,
        motivos
      });

    } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao mapear motivos de cancelamento"
      );
    }
  }
);



registrarDebugGet("/api/debug-link-dedicado-regra/:contratoId", async (req, res) => {
  try {
    const contratoId = req.params.contratoId;

    const retornoContrato = await buscar(
      "cliente_contrato",
      "cliente_contrato.id",
      contratoId,
      "1"
    );

    const contrato = retornoContrato.registros?.[0] || null;

    if (!contrato) {
      return res.status(404).json({
        erro: true,
        mensagem: "Contrato não encontrado."
      });
    }

    const cliente = await buscarClienteCache(contrato.id_cliente);

    return res.json({
      contrato: {
        id: contrato.id,
        id_cliente: contrato.id_cliente,
        cliente: cliente?.razao || cliente?.nome || cliente?.fantasia || "-",

        status: contrato.status,
        status_internet: contrato.status_internet,

        id_tipo_cliente: cliente?.id_tipo_cliente || null,
        tipo_cliente_texto: cliente?.tipo_cliente || cliente?.tipo || null,

        id_motivo_inclusao: contrato.id_motivo_inclusao || null,
        motivo_inclusao: contrato.motivo_inclusao || null,

        id_vd_contrato: contrato.id_vd_contrato,
        plano: contrato.contrato || contrato.descricao_aux_plano_venda || "-",

        id_vendedor: contrato.id_vendedor,
        data: contrato.data,
        data_ativacao: contrato.data_ativacao,
        data_renovacao: contrato.data_renovacao,
        data_expiracao: contrato.data_expiracao,

        valor_contrato:
          contrato.valor_contrato ||
          contrato.valor ||
          null,

        id_carteira_cobranca: contrato.id_carteira_cobranca || null,
        id_filial: contrato.id_filial || null
      }
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});



// COMEÇO DA API IXC // 

const CACHE = {
  minhasVendas: {},
  vendasEquipeSupervisor: {},
  financeiro: {},
  clientes: {},
  contratos: {},
  ranking: {},
  ativacoes: {}
};

const TEMPO_CACHE = {
  minhasVendas: 2 * 60 * 1000,
  vendasEquipeSupervisor: 2 * 60 * 1000,
  financeiro: 2 * 60 * 1000,
  clientes: 10 * 60 * 1000,
  contratos: 5 * 60 * 1000,
  ranking: 5 * 60 * 1000,
  ativacoes: 70 * 1000
};

function obterCache(grupo, chave) {
  const item = CACHE[grupo]?.[chave];

  if (!item) return null;

  const tempoMaximo = TEMPO_CACHE[grupo] || 60 * 1000;

  if (Date.now() - item.criadoEm > tempoMaximo) {
    delete CACHE[grupo][chave];
    return null;
  }

  return item.dados;
}

function salvarCache(grupo, chave, dados) {
  if (!CACHE[grupo]) CACHE[grupo] = {};

  CACHE[grupo][chave] = {
    criadoEm: Date.now(),
    dados
  };
}

function classificarSituacaoContrato(contrato) {
  const status = String(contrato.status || "");
  const statusInternet = String(contrato.status_internet || "");

  if (status === "A" && ["A", "FA"].includes(statusInternet)) {
    return "ATIVO";
  }

  if (status === "I") {
    return "INATIVO";
  }

  if (status === "D") {
    return "DESISTIU/CANCELADO";
  }

  if (statusInternet === "CM" || statusInternet === "CA") {
    return "BLOQUEADO";
  }

  return `STATUS ${status || "-"} / INTERNET ${statusInternet || "-"}`;
}

async function buscarVendedoresDaEquipe(equipe) {
  if (!equipe) return [];

  const [rows] = await db.query(
    `
    SELECT vendedor_id, nome
    FROM usuarios_dashboard
    WHERE equipe = ?
      AND perfil = 'vendedor'
      AND ativo = 1
      AND vendedor_id IS NOT NULL
      AND vendedor_id <> ''
    `,
    [equipe]
  );

  return rows.map(item => ({
    vendedor_id: String(item.vendedor_id),
    nome: item.nome || `Vendedor ${item.vendedor_id}`
  }));
}

app.get("/api/vendedor/minhas-vendas", exigirLogin, async (req, res) => {
  try {
    const usuario = req.session.usuario || {};
    const vendedorId = String(usuario.vendedor_id || "");

    if (!vendedorId) {
      return res.status(403).json({
        erro: true,
        mensagem: "Usuário sem vendedor_id vinculado."
      });
    }

    const hoje = new Date();
    const mesAtualSistema = `${hoje.getFullYear()}-${String(hoje.getMonth() + 1).padStart(2, "0")}`;
    const mesConsulta = String(req.query.mes || mesAtualSistema);

    if (!/^\d{4}-\d{2}$/.test(mesConsulta)) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe o mês no formato YYYY-MM."
      });
    }

    const [ano, mes] = mesConsulta.split("-");
    const dataInicio = `${ano}-${mes}-01`;
    const ultimoDiaMes = new Date(Number(ano), Number(mes), 0).getDate();
    const dataFim = `${ano}-${mes}-${String(ultimoDiaMes).padStart(2, "0")}`;

    const chaveCache = `${vendedorId}_${mesConsulta}`;
    const cache = obterCache("minhasVendas", chaveCache);

    if (cache) {
  return res.json({
    ...cache,
    vendedor: usuario.nome || usuario.usuario || "-",
    cache: true
  });
}

atualizarCacheMinhasVendas(vendedorId, mesConsulta).catch(erro => {
  console.error("Erro ao preparar cache individual de vendas:", erro.message);
});

return res.json({
  vendedor_id: vendedorId,
  vendedor: usuario.nome || usuario.usuario || "-",
  periodo: mesConsulta,
  total_vendas: 0,
  ativas: 0,
  pendentes: 0,
  canceladas: 0,
  bloqueadas: 0,
  inativas: 0,
  em_atraso: 0,
  vendas: [],
  cache: false,
  carregando_cache: true,
  mensagem: "Cache de vendas ainda está sendo preparado."
});

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      status: erro.response?.status || null,
      mensagem: erro.response?.data || erro.message
    });
  }
});


app.get("/api/supervisor/minha-equipe/vendas", exigirLogin, async (req, res) => {
  try {
    const usuario = req.session.usuario || {};

    if (usuario.perfil !== "supervisao_comercial") {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso permitido apenas para supervisão comercial."
      });
    }

    const equipe = usuario.equipe;

    if (!equipe) {
      return res.status(403).json({
        erro: true,
        mensagem: "Supervisor sem equipe vinculada."
      });
    }

    const hoje = new Date();
    const mesAtualSistema = `${hoje.getFullYear()}-${String(hoje.getMonth() + 1).padStart(2, "0")}`;
    const mesConsulta = String(req.query.mes || mesAtualSistema);

    if (!/^\d{4}-\d{2}$/.test(mesConsulta)) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe o mês no formato YYYY-MM."
      });
    }

    const chaveCache = `${equipe}_${mesConsulta}`;
    const cache = obterCache("vendasEquipeSupervisor", chaveCache);
    

    if (cache) {
      return res.json({
        ...cache,
        supervisor: usuario.nome || usuario.usuario || "-",
        cache: true
      });
    }

    const vendedoresEquipe = await buscarVendedoresDaEquipe(equipe);

    atualizarCacheVendasEquipeSupervisor(equipe, mesConsulta).catch(erro => {
      console.error("Erro ao preparar cache de vendas da equipe:", erro.message);
    });

    return res.json({
      supervisor: usuario.nome || usuario.usuario || "-",
      equipe,
      periodo: mesConsulta,
      vendedores_equipe: vendedoresEquipe,
      total_vendedores: vendedoresEquipe.length,
      total_vendas: 0,
      ativas: 0,
      pendentes_pagamento: 0,
      boletos_atraso: 0,
      vendedores: [],
      vendas: [],
      cache: false,
      carregando_cache: true,
      mensagem: "Cache de vendas da equipe ainda será preparado."
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      status: erro.response?.status || null,
      mensagem: erro.response?.data || erro.message
    });
  }
});


async function atualizarCacheMinhasVendas(vendedorId, mesConsulta) {
  const [ano, mes] = mesConsulta.split("-");
      const dataInicio = `${ano}-${mes}-01`;
      const ultimoDiaMes = new Date(
        Number(ano),
        Number(mes),
        0
      ).getDate();

  const dataFim = `${ano}-${mes}-${String(ultimoDiaMes).padStart(2, "0")}`;
  const datasPeriodo = gerarDatasPeriodo(dataInicio, dataFim);
  let contratos = [];

  for (const data of datasPeriodo) {
    const registrosDia = await buscarPorDataPaginado(
      "cliente_contrato",
      "cliente_contrato.data",
      data,
      "1000",
      10
    );

    contratos.push(...registrosDia);
  }

  const unicos = new Map();

  for (const contrato of contratos) {
    if (contrato.id) unicos.set(String(contrato.id), contrato);
  }

  contratos = [...unicos.values()];

const contratosDoVendedor = contratos.filter(c =>
  String(c.id_vendedor || "") === String(vendedorId)
);

const vendas = [];

for (const contrato of contratosDoVendedor) {
  const situacao = classificarSituacaoContrato(contrato);
  const cliente = await buscarClienteCache(contrato.id_cliente);

    // NOVO BLOCO
  const retornoOS = await buscar(
    "su_oss_chamado",
    "su_oss_chamado.id_cliente",
    contrato.id_cliente,
    "20"
  );

  const listaOS = retornoOS.registros || [];

      const osCadastro = listaOS.find(os =>
        Number(os.id_assunto) === 2
      );

      const osAtivacao = listaOS.find(os =>
        Number(os.id_assunto) === 137
      );

  vendas.push({
    contrato_id: contrato.id,
    cliente_id: contrato.id_cliente,
    cliente: cliente?.razao || cliente?.nome || cliente?.fantasia || `Cliente ID ${contrato.id_cliente}`,
    plano_id: contrato.id_vd_contrato,
    plano: contrato.contrato || contrato.descricao_aux_plano_venda || "-",
    plano_vendido: contrato.contrato || contrato.descricao_aux_plano_venda || "-",
    cidade: cliente?.cidade || contrato.cidade || "-",
    bairro: cliente?.bairro || contrato.bairro || "-",
    pendente_pagamento: String(contrato.status || "") === "P",
    boleto_em_atraso: Number(contrato.num_parcelas_atraso || 0) > 0,
      data_venda:
        osCadastro?.data_abertura ||
        contrato.data ||
        "-",

      data_ativacao:
        osAtivacao?.data_fechamento ||
        osAtivacao?.data_abertura ||
        contrato.data_ativacao ||
        "-",
    data_cancelamento: contrato.data_cancelamento || "-",
    pago_ate_data: contrato.pago_ate_data || "-",
    num_parcelas_atraso: Number(contrato.num_parcelas_atraso || 0),
    status: contrato.status || "-",
    status_internet: contrato.status_internet || "-",
    situacao
  });
} 

  const resposta = {
    vendedor_id: String(vendedorId),
    periodo: mesConsulta,
    total_vendas: vendas.length,
    ativas: vendas.filter(v => v.situacao === "ATIVO").length,
    pendentes: vendas.filter(v => v.status === "P").length,
    canceladas: vendas.filter(v => v.situacao === "DESISTIU/CANCELADO").length,
    bloqueadas: vendas.filter(v => v.situacao === "BLOQUEADO").length,
    inativas: vendas.filter(v => v.situacao === "INATIVO").length,
    em_atraso: vendas.filter(v => v.num_parcelas_atraso > 0).length,
    vendas,
    atualizado_em: new Date().toLocaleString("pt-BR")
  };

  salvarCache("minhasVendas", `${vendedorId}_${mesConsulta}`, resposta);

  return resposta;
}

async function atualizarCacheVendasEquipeSupervisor(equipe, mesConsulta) {
  const vendedoresEquipe = await buscarVendedoresDaEquipe(equipe);

  const idsVendedores = new Set(
    vendedoresEquipe.map(v => String(v.vendedor_id))
  );

  const mapaVendedores = new Map(
    vendedoresEquipe.map(v => [String(v.vendedor_id), v.nome])
  );

  const [ano, mes] = mesConsulta.split("-");
  const dataInicio = `${ano}-${mes}-01`;
  const ultimoDiaMes = new Date(Number(ano), Number(mes), 0).getDate();
  const dataFim = `${ano}-${mes}-${String(ultimoDiaMes).padStart(2, "0")}`;

  const datasPeriodo = gerarDatasPeriodo(dataInicio, dataFim);
  let contratos = [];

  for (const data of datasPeriodo) {
    const registrosDia = await buscarPorDataPaginado(
      "cliente_contrato",
      "cliente_contrato.data",
      data,
      "1000",
      10
    );

    contratos.push(...registrosDia);
  }

  const unicos = new Map();

  for (const contrato of contratos) {
    if (contrato.id) {
      unicos.set(String(contrato.id), contrato);
    }
  }

  contratos = [...unicos.values()];

  const contratosDaEquipe = contratos.filter(contrato =>
    idsVendedores.has(String(contrato.id_vendedor || ""))
  );

  const vendasEquipe = [];

  for (const contrato of contratosDaEquipe) {
    const vendedorId = String(contrato.id_vendedor || "");
    const cliente = await buscarClienteCache(contrato.id_cliente);
    const situacao = classificarSituacaoContrato(contrato);

    vendasEquipe.push({
      contrato_id: contrato.id,
      cliente_id: contrato.id_cliente,
      cliente: cliente?.razao || cliente?.nome || cliente?.fantasia || `Cliente ID ${contrato.id_cliente}`,

      vendedor_id: vendedorId,
      vendedor: mapaVendedores.get(vendedorId) || `Vendedor ${vendedorId}`,

      plano_id: contrato.id_vd_contrato,
      plano: contrato.contrato || contrato.descricao_aux_plano_venda || "-",
      plano_vendido: contrato.contrato || contrato.descricao_aux_plano_venda || "-",

      cidade: cliente?.cidade || contrato.cidade || "-",
      bairro: cliente?.bairro || contrato.bairro || "-",

      data_venda: contrato.data || "-",
      data_ativacao: contrato.data_ativacao || "-",
      data_cancelamento: contrato.data_cancelamento || "-",

      pago_ate_data: contrato.pago_ate_data || "-",
      num_parcelas_atraso: Number(contrato.num_parcelas_atraso || 0),

      status: contrato.status || "-",
      status_internet: contrato.status_internet || "-",

      pendente_pagamento: String(contrato.status || "") === "P",
      boleto_em_atraso: Number(contrato.num_parcelas_atraso || 0) > 0,

      situacao
    });
  }

  const resumoVendedores = vendedoresEquipe.map(vendedor => {
    const vendas = vendasEquipe.filter(v =>
      String(v.vendedor_id) === String(vendedor.vendedor_id)
    );

    return {
      vendedor_id: vendedor.vendedor_id,
      vendedor: vendedor.nome,
      total_vendas: vendas.length,
      ativas: vendas.filter(v => v.situacao === "ATIVO").length,
      pendentes_pagamento: vendas.filter(v => v.pendente_pagamento || v.status === "P").length,
      boletos_atraso: vendas.filter(v => v.boleto_em_atraso || Number(v.num_parcelas_atraso || 0) > 0).length,
      canceladas: vendas.filter(v => v.situacao === "DESISTIU/CANCELADO").length,
      inativas: vendas.filter(v => v.situacao === "INATIVO").length,
      bloqueadas: vendas.filter(v => v.situacao === "BLOQUEADO").length
    };
  });

  const resposta = {
    equipe,
    periodo: mesConsulta,
    total_vendedores: vendedoresEquipe.length,

    total_vendas: vendasEquipe.length,
    ativas: vendasEquipe.filter(v => v.situacao === "ATIVO").length,
    pendentes_pagamento: vendasEquipe.filter(v => v.pendente_pagamento || v.status === "P").length,
    boletos_atraso: vendasEquipe.filter(v => v.boleto_em_atraso || Number(v.num_parcelas_atraso || 0) > 0).length,
    canceladas: vendasEquipe.filter(v => v.situacao === "DESISTIU/CANCELADO").length,
    inativas: vendasEquipe.filter(v => v.situacao === "INATIVO").length,
    bloqueadas: vendasEquipe.filter(v => v.situacao === "BLOQUEADO").length,

    vendedores: resumoVendedores,
    vendas: vendasEquipe,

    debug: {
      metodo: "busca_unica_mes_filtrando_equipe",
      total_contratos_mes_ixc: contratos.length,
      total_contratos_equipe: contratosDaEquipe.length,
      periodo: mesConsulta
    },

    atualizado_em: new Date().toLocaleString("pt-BR")
  };

  salvarCache("vendasEquipeSupervisor", `${equipe}_${mesConsulta}`, resposta);

  return resposta;
}

async function atualizarCacheTodosVendedores() {
  try {
    const hoje = new Date();
    const mesAtual = `${hoje.getFullYear()}-${String(hoje.getMonth() + 1).padStart(2, "0")}`;

    const [usuarios] = await db.query(`
      SELECT vendedor_id
      FROM usuarios_dashboard
      WHERE perfil = 'vendedor'
        AND ativo = 1
        AND vendedor_id IS NOT NULL
    `);

    console.log(`Atualizando cache de ${usuarios.length} vendedores...`);

    for (const usuario of usuarios) {
      await atualizarCacheMinhasVendas(
        String(usuario.vendedor_id),
        mesAtual
      );
    }

    console.log("Cache dos vendedores atualizado.");

  } catch (erro) {
    console.error("Erro ao atualizar cache dos vendedores:", erro.message);
  }
}

registrarDebugGet("/api/debug/os-cadastro/:clienteId", async (req, res) => {
  const retorno = await buscar(
    "su_oss_chamado",
    "su_oss_chamado.id_cliente",
    req.params.clienteId,
    "20"
  );

  res.json(retorno.registros || []);
});

registrarDebugGet("/api/debug/venda-real/:clienteId", async (req, res) => {
  try {
    const clienteId = req.params.clienteId;

    const retornoOS = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.id_cliente",
      clienteId,
      "20"
    );

    const retornoAtendimentos = await buscar(
      "crm_lead",
      "crm_lead.id_cliente",
      clienteId,
      "20"
    );

    return res.json({
      clienteId,
      os: retornoOS.registros || [],
      atendimentos: retornoAtendimentos.registros || []
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});

registrarDebugGet("/api/debug/primeiro-contrato-vendedor", async (req, res) => {
  try {
    const usuario = req.session.usuario || {};
    const vendedorId = String(usuario.vendedor_id || "");

    const retornoContratos = await buscar(
      "cliente_contrato",
      "cliente_contrato.id_vendedor",
      vendedorId,
      "1"
    );

    return res.json(retornoContratos.registros?.[0] || null);

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});

registrarDebugGet("/api/debug-churn", async (req, res) => {
  try {

    const inicio = req.query.inicio;
    const fim = req.query.fim;

    const datas = gerarDatasPeriodo(inicio, fim);

    let contratos = [];

    for (const data of datas) {

      const retorno = await buscar(
        "cliente_contrato",
        "cliente_contrato.data_renovacao",
        data,
        "1000"
      );

      contratos.push(...(retorno.registros || []));
    }

    const linhas = [];

    for (const contrato of contratos) {

      const plano = await obterPlanoChurn(contrato.id_vd_contrato);

      linhas.push({

        contrato_id: contrato.id,

        cliente_id: contrato.id_cliente,

        vendedor_id: contrato.id_vendedor,

        data_renovacao: contrato.data_renovacao,

        status: contrato.status,

        status_internet: contrato.status_internet,

        plano: plano?.nome,

        valor: numeroIXC(plano?.valor_contrato)

      });

    }

    res.json(linhas);

  } catch (erro) {

    res.status(500).json({
      erro: erro.message
    });

  }
});

registrarDebugGet("/api/debug-churn-os", async (req, res) => {
  try {
    const retorno = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.setor",
      "73",
      "20"
    );

    res.json({
      total: retorno.registros?.length || 0,
      registros: retorno.registros || []
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      status: erro.response?.status || null,
      mensagem: erro.response?.data || erro.message
    });
  }
});


registrarDebugGet("/api/debug-mensagens-os/:id", async (req, res) => {
  try {
    const retorno = await buscar(
      "su_oss_chamado_mensagem",
      "su_oss_chamado_mensagem.id_chamado",
      req.params.id,
      "50"
    );

    res.json(retorno.registros || []);
  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});

registrarDebugGet("/api/debug-os-completo/:id", async (req, res) => {
  try {
    const os = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.id",
      req.params.id,
      "1"
    );

    const mensagens = await buscar(
      "su_oss_chamado_mensagem",
      "su_oss_chamado_mensagem.id_chamado",
      req.params.id,
      "50"
    );

    res.json({
      os: os.registros?.[0],
      mensagens: mensagens.registros || []
    });
  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});

let cachePagamentosAtivacao = null;
let cachePagamentosAtivacaoCriadoEm = 0;
const TEMPO_CACHE_PAGAMENTOS = 60 * 1000;

app.get("/api/pagamentos-ativacao", exigirLogin, async (req, res) => {
  try {
    const agora = Date.now();
    const cacheValido =
      cachePagamentosAtivacao &&
      agora - cachePagamentosAtivacaoCriadoEm < TEMPO_CACHE_PAGAMENTOS;

    if (cacheValido) {
      return res.json({
        ...cachePagamentosAtivacao,
        cache: true,
        atualizado_em: new Date(cachePagamentosAtivacaoCriadoEm).toLocaleString("pt-BR")
      });
    }

    const [retornoPagos, retornoAbertos] = await Promise.all([
      buscar("fn_areceber", "fn_areceber.status", "R", "200"),
      buscar("fn_areceber", "fn_areceber.status", "A", "100")
    ]);

    const pagamentos = [
      ...(retornoPagos.registros || []),
      ...(retornoAbertos.registros || [])
    ];

    const resultado = [];

    for (const pagamento of pagamentos) {
      const contratoId = pagamento.id_contrato_avulso;

      if (!contratoId || contratoId === "0") {
        continue;
      }

      const valorPago = Number(pagamento.valor_recebido || pagamento.valor || 0);

      if (valorPago < 9.9 || valorPago > 400) {
        continue;
      }

      const [cliente, contrato] = await Promise.all([
        buscarClienteCache(pagamento.id_cliente),
        buscarContratoCache(contratoId)
      ]);

      if (contrato?.status === "A") {
        continue;
      }

      const idVendedor =
        contrato?.id_vendedor ||
        cliente?.id_vendedor ||
        "";

      const retornoOS = await buscar(
        "su_oss_chamado",
        "su_oss_chamado.id_contrato_kit",
        contratoId,
        "30"
      );

      const ordens = retornoOS.registros || [];

      const osAguardandoPagamento = ordens.find((os) =>
        (
          os.id_assunto === "641" &&
          os.id_wfl_tarefa === "1113" &&
          os.status !== "F"
        ) ||
        (
          os.id_assunto === "202" &&
          os.id_wfl_tarefa === "260" &&
          os.status !== "F"
        )
      );

      if (!osAguardandoPagamento) {
        continue;
      }

      const osAtivacao = ordens.find((os) =>
        ["137", "599", "247"].includes(String(os.id_assunto)) ||
        ["25", "1005", "214"].includes(String(os.id_wfl_tarefa))
      );

      if (osAtivacao) {
        continue;
      }

        const statusAcesso = String(contrato?.status_internet || "");
        const termoAssinado = statusAcesso === "A";

        const aguardandoPagamento = pagamento.status === "A";
        const pago = pagamento.status === "R";

        const liberadoParaOS =
          pago &&
          termoAssinado &&
          Boolean(osAguardandoPagamento);

        let etapaOperacional = "AGUARDANDO PAGAMENTO";

        if (pago && !termoAssinado) {
          etapaOperacional = "AGUARDANDO ASSINATURA";
        }

        if (liberadoParaOS) {
          etapaOperacional = "LIBERADO PARA ABRIR OS";
        }

        const statusOperacional = etapaOperacional;

      resultado.push({
        id_pagamento: pagamento.id,
        cliente_id: pagamento.id_cliente,
        cliente: cliente?.razao || `Cliente ID ${pagamento.id_cliente}`,
        vendedor_id: idVendedor,
        vendedor: vendedores[idVendedor] || `Vendedor ID ${idVendedor}`,
        contrato: contratoId,
        valor: pagamento.valor_recebido || pagamento.valor,
        data_pagamento: pagamento.pagamento_data,
        baixa_data: pagamento.baixa_data,
        data_vencimento: pagamento.data_vencimento,
        tipo_recebimento: pagamento.tipo_recebimento,
        boleto: pagamento.boleto,
        os_aguardando_pagamento: osAguardandoPagamento?.id || "",
        os_ativacao: "",
        status_pagamento: pagamento.status,
        status: statusOperacional,
        status_acesso: statusAcesso,
        termo_assinado: termoAssinado,
        pode_abrir_os: liberadoParaOS,
        liberado_para_os: liberadoParaOS,
        status_termo: termoAssinado ? "CONTRATO ASSINADO" : "AGUARDANDO ASSINATURA",
        etapa_operacional: etapaOperacional,
        informacoes_ativacao: osAguardandoPagamento?.mensagem_resposta || osAguardandoPagamento?.mensagem || ""
      });
    }

      const resposta = {
        total: resultado.length,
        pagamentos: resultado
      };

      cachePagamentosAtivacao = JSON.parse(JSON.stringify(resposta));
      cachePagamentosAtivacaoCriadoEm = Date.now();

      res.json({
        ...resposta,
        cache: false,
        atualizado_em: new Date(cachePagamentosAtivacaoCriadoEm).toLocaleString("pt-BR")
      });


  } catch (erro) {
    res.status(500).json({
      erro: true,
      status: erro.response?.status || null,
      mensagem: erro.response?.data || erro.message
    });
  }
});

registrarDebugGet("/api/debug-link-cliente/:clienteId", async (req, res) => {
  try {
    const clienteId = req.params.clienteId;

    const cliente = await buscarClienteCache(clienteId);

    res.json({
      cliente_id: clienteId,
      cliente
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});

app.get("/api/confirmacoes", exigirLogin, async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT *
      FROM confirmacoes_os
      ORDER BY data_confirmacao DESC
    `);

    const atual = {};
    const historico = rows.map((item) => {
      const registro = {
        osId: item.os_id,
        cliente: item.cliente || "-",
        vendedor: item.vendedor || "-",
        tecnico: item.tecnico || "-",
        dataAgendamento: item.data_agendamento || "-",
        turno: item.turno || "-",
        dataConfirmacao: item.data_confirmacao
      };

      atual[item.os_id] = registro;
      return registro;
    });

    res.json({ atual, historico });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

app.post("/api/confirmacoes", exigirLogin, async (req, res) => {
  try {
    const {
      osId,
      cliente,
      vendedor,
      tecnico,
      dataAgendamento,
      turno
    } = req.body;

    if (!osId) {
      return res.status(400).json({
        erro: true,
        mensagem: "ID da O.S. é obrigatório."
      });
    }

    const usuario =
      req.session?.usuario?.nome ||
      req.session?.usuario?.usuario ||
      "-";

    await db.query(
      `
      INSERT INTO confirmacoes_os
        (os_id, cliente, vendedor, tecnico, data_agendamento, turno, confirmado_por)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        cliente = VALUES(cliente),
        vendedor = VALUES(vendedor),
        tecnico = VALUES(tecnico),
        data_agendamento = VALUES(data_agendamento),
        turno = VALUES(turno),
        confirmado_por = VALUES(confirmado_por),
        data_confirmacao = NOW()
      `,
      [
        String(osId),
        cliente || "-",
        vendedor || "-",
        tecnico || "-",
        dataAgendamento || "-",
        turno || "-",
        usuario
      ]
    );
    

    await db.query(
  `
        INSERT INTO historico_confirmacoes
          (
            os_id,
            cliente,
            vendedor,
            tecnico,
            tecnico_id,
            data_agendamento,
            turno,
            confirmado_por
          )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          String(osId),
          cliente || "-",
          vendedor || "-",
          tecnico || "-",
          "",
          dataAgendamento || "-",
          turno || "-",
          usuario
        ]
      );

      await db.query(
        "DELETE FROM lista_confirmacao_os WHERE os_id = ?",
        [String(osId)]
      );

      listaConfirmacaoAtual = listaConfirmacaoAtual.filter(item =>
      String(item.os || item.osId || item.id || item.os_id) !== String(osId)
      );

      await registrarLogSistema(req, {
          acao: "CONFIRMOU_CLIENTE",
          modulo: "Confirmações",
          os_id: String(osId),
          cliente: cliente || "-",
          detalhes: `Data agendamento: ${dataAgendamento || "-"} | Turno: ${turno || "-"}`
        });

    const [rows] = await db.query(`
      SELECT *
      FROM confirmacoes_os
      ORDER BY data_confirmacao DESC
    `);

    const atual = {};
    const historico = rows.map((item) => {
      const registro = {
        osId: item.os_id,
        cliente: item.cliente || "-",
        vendedor: item.vendedor || "-",
        tecnico: item.tecnico || "-",
        dataAgendamento: item.data_agendamento || "-",
        turno: item.turno || "-",
        dataConfirmacao: item.data_confirmacao
      };

      atual[item.os_id] = registro;
      return registro;
    });

    res.json({
      sucesso: true,
      confirmacoes: { atual, historico }
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

app.get("/api/relatorios/reagendamentos", exigirLogin, async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT
        id,
        os_id,
        cliente,
        vendedor,
        tecnico,
        tecnico_id,
        contrato,
        motivo,
        reagendado_por,
        DATE_FORMAT(data_reagendamento, '%d/%m/%Y %H:%i') AS data_reagendamento
      FROM historico_reagendamentos
      ORDER BY id DESC
      LIMIT 200
    `);

    res.json({
      total: rows.length,
      reagendamentos: rows
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

app.post("/api/confirmacoes/limpar", exigirLogin, (req, res) => {
  if (!confirmacoesOS.historico) confirmacoesOS.historico = [];

  confirmacoesOS.atual = {};

  res.json({
    sucesso: true,
    mensagem: "Lista atual de confirmação limpa com sucesso. Histórico preservado.",
    confirmacoes: confirmacoesOS
  });
});

function converterDataAgendaConfirmacao(dataHora) {
  if (!dataHora) return null;

  const [data] = String(dataHora).split(" ");
  const partes = data.split("/");

  if (partes.length !== 3) return null;

  const [dia, mes, ano] = partes;

  return new Date(`${ano}-${mes}-${dia}T00:00:00`);
}

function minutosAgora() {
  const agora = new Date();
  return agora.getHours() * 60 + agora.getMinutes();
}

function inicioHoje() {
  const hoje = new Date();
  hoje.setHours(0, 0, 0, 0);
  return hoje;
}

app.get("/api/lista-confirmacao/controle", exigirLogin, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT referencia FROM lista_confirmacao_controle WHERE id = 1 LIMIT 1"
    );

    res.json({
      referencia: rows[0]?.referencia || ""
    });
  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

app.get("/api/lista-confirmacao", exigirLogin, async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT
        os_id AS os,
        cliente,
        vendedor,
        tecnico,
        tecnico_id,
        data_agenda,
        turno
      FROM lista_confirmacao_os
      ORDER BY data_agenda ASC, cliente ASC
    `);

    res.json(rows);

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});

app.post("/api/lista-confirmacao", exigirLogin, async (req, res) => {
  try {
    const { lista, substituirLista } = req.body;

    if (!Array.isArray(lista)) {
      return res.status(400).json({
        erro: true,
        mensagem: "Lista de confirmação inválida."
      });
    }

    const idsGrade = lista
      .map(item => String(item.os || item.osId || item.id || item.os_id || ""))
      .filter(Boolean);

    if (substituirLista === true) {
      await db.query("DELETE FROM lista_confirmacao_os");

      if (idsGrade.length > 0) {
        await db.query(
          `
          DELETE FROM confirmacoes_os
          WHERE os_id NOT IN (${idsGrade.map(() => "?").join(",")})
          `,
          idsGrade
        );
      } else {
        await db.query("DELETE FROM confirmacoes_os");
      }
    }

    const [confirmados] = await db.query(`
      SELECT os_id
      FROM confirmacoes_os
    `);

    const osConfirmadas = new Set(
      confirmados.map(item => String(item.os_id))
    );

    for (const item of lista) {
      const osId = String(item.os || item.osId || item.id || item.os_id || "");

      if (!osId) continue;
      if (osConfirmadas.has(osId)) continue;

      await db.query(
        `
        INSERT INTO lista_confirmacao_os
          (os_id, cliente, vendedor, tecnico, tecnico_id, data_agenda, turno)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          cliente = VALUES(cliente),
          vendedor = VALUES(vendedor),
          tecnico = VALUES(tecnico),
          tecnico_id = VALUES(tecnico_id),
          data_agenda = VALUES(data_agenda),
          turno = VALUES(turno)
        `,
        [
          osId,
          item.cliente || "-",
          item.vendedor || "-",
          item.tecnico || "-",
          item.tecnico_id || item.tecnicoId || "",
          item.data_agenda || item.dataAgendamento || "",
          item.turno || ""
        ]
      );
    }

    const [rows] = await db.query(`
      SELECT
        os_id AS os,
        cliente,
        vendedor,
        tecnico,
        tecnico_id,
        data_agenda,
        turno
      FROM lista_confirmacao_os
      ORDER BY data_agenda ASC, cliente ASC
    `);

    return res.json({
      sucesso: true,
      lista: rows
    });

  } catch (erro) {
    console.error("ERRO /api/lista-confirmacao:", erro);

    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

app.post("/api/lista-confirmacao/limpar-finalizadas", exigirLogin, async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT os_id
      FROM lista_confirmacao_os
    `);

    let verificadas = 0;
    let removidas = 0;

    for (const item of rows) {
      verificadas++;

      const retornoOS = await buscar(
        "su_oss_chamado",
        "su_oss_chamado.id",
        String(item.os_id),
        "1"
      );

      const osAtual = retornoOS.registros?.[0];

      if (!osAtual || String(osAtual.status) === "F") {
        await db.query(
          "DELETE FROM lista_confirmacao_os WHERE os_id = ?",
          [String(item.os_id)]
        );

        removidas++;
      }
    }
    
    await registrarLogSistema(req, {
        acao: "LIMPOU_FINALIZADAS_LISTA_CONFIRMACAO",
        modulo: "Confirmações",
        detalhes: `Verificadas: ${verificadas}. Removidas: ${removidas}.`
      });

    res.json({
      sucesso: true,
      mensagem: "Limpeza de O.S. finalizadas concluída.",
      verificadas,
      removidas
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});

app.post("/api/lista-confirmacao/limpar", exigirLogin, async (req, res) => {
  try {
    await db.query("DELETE FROM lista_confirmacao_os");
    confirmacoesOS.atual = {};

    await db.query("DELETE FROM confirmacoes_os");

    await registrarLogSistema(req, {
        acao: "LIMPOU_LISTA_CONFIRMACAO",
        modulo: "Confirmações",
        detalhes: "Usuário limpou a lista atual de confirmação."
      });

    res.json({
      sucesso: true,
      mensagem: "Lista de confirmação limpa com sucesso. Histórico preservado.",
      lista: [],
      confirmacoes: confirmacoesOS
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

registrarDebugPost("/api/os/:id/teste-finalizar-pagamento", async (req, res) => {
  try {
    const idOS = req.params.id;

    const retornoOS = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.id",
      idOS,
      "1"
    );

    const os = retornoOS.registros?.[0];

    if (!os) {
      return res.status(404).json({
        erro: true,
        mensagem: "O.S. não encontrada."
      });
    }

    const payload = {
      id_chamado: idOS,
      status: "F",
      id_evento: "6",
      mensagem: os.mensagem_resposta || "",
      historico: "",
      id_tecnico: os.id_tecnico || "921",
      id_equipe: "0",
      finaliza_processo: "N",
      data_inicio: "",
      data_final: "",
      id_proxima_tarefa: "25",
      id_su_diagnostico: "1453",
      id_diagnostico_especifico: "0",
      tipo_cobranca: "NENHUM",
      id_operador: "677"
    };

    res.json({
      teste: true,
      os: {
        id: os.id,
        status: os.status,
        id_assunto: os.id_assunto,
        id_wfl_tarefa: os.id_wfl_tarefa,
        contrato: os.id_contrato_kit,
        cliente: os.id_cliente
      },
      payload
    });
  } catch (erro) {
    res.status(500).json({
      erro: true,
      status: erro.response?.status || null,
      mensagem: erro.response?.data || erro.message
    });
  }
});

app.post( "/api/os/:id/finalizar-pagamento-ativacao", exigirLogin, exigirPermissao("finalizar_pagamento_ativacao"), async (req, res) => {
    try {
      const idOS = req.params.id;
      let { mensagem } = req.body;

      const retornoOS = await buscar(
        "su_oss_chamado",
        "su_oss_chamado.id",
        idOS,
        "1"
      );

      const os = retornoOS.registros?.[0];

      if (!os) {
        return res.status(404).json({
          erro: true,
          mensagem: "O.S. não encontrada."
        });
      }

      if (String(os.status || "") === "F") {
        return res.status(400).json({
          erro: true,
          mensagem: "Esta O.S. já está finalizada."
        });
      }

      const assuntoId = String(os.id_assunto || "");
      const tarefaAtual = String(os.id_wfl_tarefa || "");

      const ehPagamentoAtivacaoNormal =
        assuntoId === "641" &&
        tarefaAtual === "1113";

      const ehPagamentoFibrasil =
        tarefaAtual === "260" ||
        String(os.mensagem || "")
          .toUpperCase()
          .includes("PROCESSO DE ATIVAÇÃO FIBRASIL");

      if (
        !ehPagamentoAtivacaoNormal &&
        !ehPagamentoFibrasil
      ) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "Esta O.S. não é de pagamento de ativação reconhecida."
        });
      }

      if (
        typeof mensagem !== "string" ||
        !mensagem.trim()
      ) {
        const cliente = await buscarCliente(
          os.id_cliente
        );

        mensagem = cliente?.alerta || "";
      }

      if (
        typeof mensagem !== "string" ||
        !mensagem.trim()
      ) {
        return res.status(400).json({
          erro: true,
          mensagem:
            "Não foi encontrada observação no campo Alerta do cliente."
        });
      }

      const contrato = await buscarContrato(
        os.id_contrato_kit
      );

      const ehReativacaoComercial =
        String(
          contrato?.id_motivo_inclusao || ""
        ) === "8";

      const proximaTarefa = ehPagamentoFibrasil
        ? "214"
        : ehReativacaoComercial
          ? "1005"
          : "25";

      const fluxo = ehPagamentoFibrasil
        ? "ATIVAÇÃO FIBRASIL"
        : ehReativacaoComercial
          ? "REATIVAÇÃO COMERCIAL"
          : "ATIVAÇÃO COMERCIAL";

      const agora = new Date()
        .toISOString()
        .slice(0, 19)
        .replace("T", " ");

      const operadorIXC = String(
        req.session.usuario?.colaborador_ixc_id ||
        "677"
      );

      const payload = {
        id_chamado: idOS,
        status: "F",
        id_evento: "6",
        mensagem: mensagem.trim(),
        historico: "",
        id_tecnico: operadorIXC,
        id_operador: operadorIXC,
        id_equipe: "0",
        finaliza_processo: "N",
        gera_comissao: "S",
        data_inicio: agora,
        data_final: agora,
        id_proxima_tarefa: proximaTarefa,
        id_su_diagnostico: "1453",
        id_diagnostico_especifico: "0",
        tipo_cobranca: "NENHUM"
      };

            console.log(
              "[ABERTURA ATIVACAO] Payload enviado ao IXC:",
              {
                os_origem: idOS,
                contrato_id:
                  os.id_contrato_kit ||
                  os.id_contrato ||
                  null,
                cliente_id:
                  os.id_cliente ||
                  null,
                assunto_id:
                  String(os.id_assunto || ""),
                tarefa_atual:
                  String(os.id_wfl_tarefa || ""),
                fluxo,
                proxima_tarefa:
                  proximaTarefa,
                operador_ixc:
                  operadorIXC,
                payload
              }
            );

            const response = await api.post(
              "/su_oss_chamado_fechar",
              payload,
              {
                headers: {
                  ixcsoft: "inserir"
                }
              }
            );

            console.log(
              "[ABERTURA ATIVACAO] Resposta do IXC:",
              {
                os_origem:
                  idOS,
                contrato_id:
                  os.id_contrato_kit ||
                  os.id_contrato ||
                  null,
                cliente_id:
                  os.id_cliente ||
                  null,
                fluxo,
                proxima_tarefa:
                  proximaTarefa,
                resposta:
                  response.data
              }
            );

      if (response.data?.type !== "success") {
        return res.status(400).json({
          erro: true,
          mensagem:
            response.data?.message ||
            "IXC não finalizou a O.S.",
          retorno: response.data
        });
      }

      let osOperacionalLocalizada = null;
      let resultadoTesteVelocidade = null;

try {
  osOperacionalLocalizada =
    await localizarOSOperacionalCriada({
      contratoId:
        os.id_contrato_kit ||
        os.id_contrato ||
        null,

      clienteId:
        os.id_cliente ||
        null,

      osPagamentoId:
        idOS,

      tentativas: 6,
      intervaloMs: 1000
    });

  if (osOperacionalLocalizada) {
    console.log(
      "[TESTE VELOCIDADE] O.S. operacional localizada com sucesso:",
      {
        fluxo,
        os_pagamento_id:
          idOS,

        os_operacional_id:
          osOperacionalLocalizada.id,

        contrato_id:
          osOperacionalLocalizada.id_contrato_kit ||
          osOperacionalLocalizada.id_contrato ||
          null,

        cliente_id:
          osOperacionalLocalizada.id_cliente ||
          null,

        assunto_id:
          osOperacionalLocalizada.id_assunto ||
          null,

        status:
          osOperacionalLocalizada.status ||
          null,

        tarefa:
          osOperacionalLocalizada.id_wfl_tarefa ||
          null,

        parametro:
          osOperacionalLocalizada.id_wfl_param_os ||
          null

          
      }
    );

    try {
  resultadoTesteVelocidade =
    await criarOSAnexoTesteVelocidade({
      osOperacional:
        osOperacionalLocalizada
    });
} catch (erroTesteVelocidade) {
  resultadoTesteVelocidade = {
    sucesso: false,
    erro: true,
    mensagem:
      erroTesteVelocidade?.message ||
      "Erro ao criar a O.S. de teste de velocidade."
  };

  console.error(
    "[TESTE VELOCIDADE] Falha na criação ou vinculação da O.S. 679:",
    {
      fluxo,
      os_pagamento_id:
        idOS,
      os_operacional_id:
        osOperacionalLocalizada.id,
      contrato_id:
        osOperacionalLocalizada.id_contrato_kit ||
        osOperacionalLocalizada.id_contrato ||
        null,
      cliente_id:
        osOperacionalLocalizada.id_cliente ||
        null,
      mensagem:
        erroTesteVelocidade?.message ||
        null,
      retorno_ixc:
        erroTesteVelocidade?.response?.data ||
        null
    }
  );
}


  } else {
    console.warn(
      "[TESTE VELOCIDADE] O.S. operacional não localizada após as tentativas:",
      {
        fluxo,
        os_pagamento_id:
          idOS,

        contrato_id:
          os.id_contrato_kit ||
          os.id_contrato ||
          null,

        cliente_id:
          os.id_cliente ||
          null
      }
    );
  }
} catch (erroLocalizacao) {
  console.error(
    "[TESTE VELOCIDADE] Erro ao localizar a O.S. operacional:",
    {
      fluxo,
      os_pagamento_id:
        idOS,

      contrato_id:
        os.id_contrato_kit ||
        os.id_contrato ||
        null,

      cliente_id:
        os.id_cliente ||
        null,

      mensagem:
        erroLocalizacao?.message ||
        null,

      retorno_ixc:
        erroLocalizacao?.response?.data ||
        null
    }
  );
}

      let retornoLimpezaAlerta = null;

      try {
        retornoLimpezaAlerta =
          await limparAlertaCliente(
            os.id_cliente
          );
      } catch (erroLimpeza) {
        retornoLimpezaAlerta = {
          erro: true,
          mensagem:
            erroLimpeza.response?.data ||
            erroLimpeza.message
        };
      }

      await registrarLogSistema(req, {
        acao:
          "FINALIZOU_PAGAMENTO_ATIVACAO",
        modulo:
          "Pagamentos de Ativação",
        os_id:
          String(idOS),
        cliente:
          os.id_cliente
            ? `Cliente ID ${os.id_cliente}`
            : null,
        detalhes:
          `Fluxo: ${fluxo} | Próxima tarefa: ${proximaTarefa}`
      });

      return res.json({
        sucesso: true,
        mensagem:
          `O.S. de pagamento finalizada. Fluxo enviado para ${fluxo}.`,
        fluxo,
        proxima_tarefa:
          proximaTarefa,
              os_operacional: osOperacionalLocalizada
      ? {
          id:
            osOperacionalLocalizada.id,
          assunto_id:
            osOperacionalLocalizada.id_assunto,
          contrato_id:
            osOperacionalLocalizada.id_contrato_kit ||
            osOperacionalLocalizada.id_contrato ||
            null,
          cliente_id:
            osOperacionalLocalizada.id_cliente ||
            null
        }
      : null,

    teste_velocidade:
      resultadoTesteVelocidade,
        limpeza_alerta:
          retornoLimpezaAlerta,
        os: {
          id:
            os.id,
          contrato:
            os.id_contrato_kit,
          cliente:
            os.id_cliente
        },
        retorno:
          response.data
      });
    } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao finalizar pagamento de ativação"
      );
    }
  }
);

async function registrarLogSistema(req, dados = {}) {
  try {
    const usuario = req.session?.usuario || {};

    await db.query(
      `
      INSERT INTO logs_sistema
        (usuario_id, usuario_nome, usuario_perfil, acao, modulo, os_id, cliente, detalhes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        usuario.id || null,
        usuario.nome || usuario.usuario || null,
        usuario.perfil || null,
        dados.acao || "-",
        dados.modulo || null,
        dados.os_id || null,
        dados.cliente || null,
        dados.detalhes || null
      ]
    );
  } catch (erro) {
    console.error("Erro ao registrar log do sistema:", erro.message);
  }
}

app.get("/api/relatorios/logs-sistema", exigirLogin, async (req, res) => {
  try {
    const usuarioLogado = req.session.usuario;

    if (!podeGerenciarMetas(usuarioLogado)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso negado."
      });
    }

    const [logs] = await db.query(
      `
      SELECT
        id,
        usuario_nome,
        usuario_perfil,
        acao,
        modulo,
        os_id,
        cliente,
        detalhes,
        criado_em
      FROM logs_sistema
      ORDER BY criado_em DESC
      LIMIT 500
      `
    );

    res.json({ logs });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

registrarDebugGet(
  "/api/debug/ixc/oss-contrato/:contratoId",
  async (req, res) => {
    try {
      const contratoId =
        String(
          req.params.contratoId || ""
        );

      const retorno = await buscar(
        "su_oss_chamado",
        "su_oss_chamado.id_contrato_kit",
        contratoId,
        "100"
      );

      const ordens =
        retorno.registros || [];

      const resultado = ordens
        .map(os => ({
          id: os.id,
          protocolo: os.protocolo,
          assunto_id: String(
            os.id_assunto || ""
          ),
          status: os.status,
          cliente_id: os.id_cliente,
          contrato_id:
            os.id_contrato_kit ||
            os.id_contrato ||
            null,
          setor_id:
            os.setor ||
            os.id_setor ||
            null,
          tecnico_id:
            os.id_tecnico ||
            null,
          origem:
            os.origem_os_aberta ||
            os.origem ||
            null,
          id_wfl_tarefa:
            os.id_wfl_tarefa ||
            null,
          id_wfl_param_os:
            os.id_wfl_param_os ||
            null,
          id_os_anterior:
            os.id_oss_chamado ||
            null,
          data_abertura:
            os.data_abertura ||
            null,
          descricao:
            os.mensagem ||
            ""
        }))
        .sort(
          (a, b) =>
            Number(b.id || 0) -
            Number(a.id || 0)
        );

      return res.json({
        sucesso: true,
        contrato_id: contratoId,
        total: resultado.length,
        ativacoes: resultado.filter(
          item =>
            item.assunto_id === "137"
        ),
        anexos_teste_velocidade:
          resultado.filter(
            item =>
              item.assunto_id === "679"
          ),
        ordens: resultado
      });
    } catch (erro) {
      return res.status(500).json({
        erro: true,
        mensagem:
          erro.response?.data ||
          erro.message
      });
    }
  }
);

registrarDebugGet("/api/debug-ranking-churn-classificacao", async (req, res) => {
  try {
    const dataInicial = req.query.inicio;
    const dataFinal = req.query.fim;

    if (!dataInicial || !dataFinal) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe inicio e fim."
      });
    }

    const retornoOSChurn = await buscar(
      "su_oss_chamado",
      "su_oss_chamado.setor",
      "73",
      "1000"
    );

    const linhas = [];

    for (const os of retornoOSChurn.registros || []) {
      const dataOS = String(
        os.data_fechamento ||
        os.data_final ||
        os.ultima_atualizacao ||
        ""
      ).slice(0, 10);

      if (dataOS < dataInicial || dataOS > dataFinal) continue;

      const texto = `${os.mensagem || ""}\n${os.mensagem_resposta || ""}`;

      const matchPlanoAntigo = texto.match(
        /PLANO\s+ANTIGO:[\s\S]*?VALOR:\s*R\$\s*([\d.,]+)/i
      );

      const matchPlanoNovo = texto.match(
        /PLANO\s+NOVO:[\s\S]*?VALOR:\s*R\$\s*([\d.,]+)/i
      );

      const valorAntigo = matchPlanoAntigo ? numeroIXC(matchPlanoAntigo[1]) : 0;
      const valorNovo = matchPlanoNovo ? numeroIXC(matchPlanoNovo[1]) : 0;

      const tipo = await classificarRenovacaoChurnPorTexto(texto);

      linhas.push({
        os_id: os.id,
        contrato_id: os.id_contrato_kit,
        cliente_id: os.id_cliente,
        tecnico_id: os.id_tecnico,
        data: dataOS,
        status: os.status,
        valor_antigo: valorAntigo,
        valor_novo: valorNovo,
        tipo_detectado: tipo,
        entra_no_ranking: tipo !== "NAO_IDENTIFICADO"
      });
    }

    res.json({
      periodo: { inicio: dataInicial, fim: dataFinal },
      total_os_analisadas: linhas.length,
      entram_no_ranking: linhas.filter(l => l.entra_no_ranking).length,
      ignoradas: linhas.filter(l => !l.entra_no_ranking).length,
      linhas
    });

  } catch (erro) {
    res.status(500).json({
      erro: true,
      mensagem: erro.response?.data || erro.message
    });
  }
});

app.get("/api/regras-receita-ranking", exigirLogin, exigirPermissao("gerenciar_metas"), async (req, res) => {
  try {
    const mes = req.query.mes;

    if (!mes) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe o mês no formato YYYY-MM."
      });
    }

    const [rows] = await db.query(
      `
      SELECT
        id,
        id_plano_venda,
        mes,
        tipo_regra,
        valor_cheio,
        primeira_mensalidade,
        receita_calculada,
        ativo,
        atualizado_em
      FROM regras_receita_ranking
      WHERE mes = ?
      ORDER BY id_plano_venda
      `,
      [mes]
    );

    res.json({ mes, regras: rows });

  } catch (erro) {
        return responderErroInterno(
          req,
          res,
          erro,
          "Erro ao consultar regras de receita"
        );
  }
});

app.post("/api/regras-receita-ranking", exigirLogin, exigirPermissao("gerenciar_metas"), async (req, res) => {
  try {
    const usuarioLogado = req.session.usuario;

    if (!podeGerenciarMetas(usuarioLogado)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Acesso negado."
      });
    }

    const {
      mes,
      id_plano_venda,
      valor_cheio,
      primeira_mensalidade
    } = req.body || {};

    if (!mes || !id_plano_venda || !valor_cheio || !primeira_mensalidade) {
      return res.status(400).json({
        erro: true,
        mensagem: "Mês, ID do plano, valor cheio e primeira mensalidade são obrigatórios."
      });
    }

    await db.query(
      `
      INSERT INTO regras_receita_ranking
        (id_plano_venda, mes, tipo_regra, valor_cheio, primeira_mensalidade, ativo)
      VALUES (?, ?, 'media_12_meses', ?, ?, 1)
      ON DUPLICATE KEY UPDATE
        tipo_regra = 'media_12_meses',
        valor_cheio = VALUES(valor_cheio),
        primeira_mensalidade = VALUES(primeira_mensalidade),
        ativo = 1
      `,
      [
        String(id_plano_venda),
        mes,
        Number(valor_cheio || 0),
        Number(primeira_mensalidade || 0)
      ]
    );

    for (const chave of Object.keys(cacheRankingReceita)) {
      if (chave.includes(mes)) {
        delete cacheRankingReceita[chave];
      }
    }

    res.json({
      sucesso: true,
      mensagem: "Regra de receita salva com sucesso."
    });

  } catch (erro) {
      return responderErroInterno(
        req,
        res,
        erro,
        "Erro ao salvar regra de receita"
      );
  }
});

atualizarCacheAtivacoes();
atualizarCacheTodosVendedores();

setInterval(() => {
  atualizarCacheAtivacoes();
}, 60 * 1000);

setInterval(() => {
  atualizarCacheTodosVendedores();
}, 10 * 60 * 1000);

setTimeout(() => {
  executarSyncPenalidadesBackofficeAtual();
}, 30 * 1000);

setInterval(() => {
  executarSyncPenalidadesBackofficeAtual();
}, INTERVALO_SYNC_PENALIDADES_BACKOFFICE);



function podeAcessarRelatorioReversao(req) {
  const usuario = req.session?.usuario || {};
  const permissoes = usuario.permissoes || [];

  return (
    usuario.perfil === "super_admin" ||
    usuario.perfil === "gerencial" ||
    usuario.perfil === "vendedor" ||
    usuario.perfil === "supervisao_midia" ||
    permissoes.includes("ver_relatorio_reversao")
  );
}

function podeVerRelatoriosReversaoEquipe(req) {
  const usuario = req.session?.usuario || {};
  const permissoes = usuario.permissoes || [];

  return (
    usuario.perfil === "super_admin" ||
    usuario.perfil === "gerencial" ||
    usuario.perfil === "supervisao_midia" ||
    permissoes.includes("ver_relatorio_reversao_equipe")
  );
}

app.get("/api/relatorio-reversao/meu", exigirLogin, async (req, res) => {
  try {
    if (!podeAcessarRelatorioReversao(req)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Você não tem permissão para acessar este relatório."
      });
    }

    const usuario = req.session.usuario;
    const data = req.query.data || new Date().toISOString().slice(0, 10);

    const [relatorios] = await db.query(
      `
      SELECT *
      FROM relatorios_reversao_diaria
      WHERE usuario_id = ?
        AND data_referencia = ?
      LIMIT 1
      `,
      [usuario.id, data]
    );

    if (!relatorios.length) {
      return res.json({
        sucesso: true,
        relatorio: null,
        sem_viabilidade: []
      });
    }

    const relatorio = relatorios[0];

    const [semViabilidade] = await db.query(
      `
      SELECT id, localizacao, qtd
      FROM relatorios_reversao_sem_viabilidade
      WHERE relatorio_id = ?
      ORDER BY id ASC
      `,
      [relatorio.id]
    );

    return res.json({
      sucesso: true,
      relatorio,
      sem_viabilidade: semViabilidade
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

app.post("/api/relatorio-reversao/meu", exigirLogin, async (req, res) => {
  const conexao = await db.getConnection();

  try {
    if (!podeAcessarRelatorioReversao(req)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Você não tem permissão para enviar este relatório."
      });
    }

    const usuario = req.session.usuario;
    const body = req.body || {};

    const dataReferencia = body.data_referencia || new Date().toISOString().slice(0, 10);
    const locais = Array.isArray(body.sem_viabilidade_locais)
      ? body.sem_viabilidade_locais
      : [];

    await conexao.beginTransaction();

    await conexao.query(
      `
      INSERT INTO relatorios_reversao_diaria (
        usuario_id,
        vendedor_nome,
        data_referencia,
        ligacoes_ativas,
        corporativo_em_negociacao,
        corporativo_outros_setores,
        corporativo_sem_interacao,
        vencemos,
        instalacao_inviavel,
        perdemos,
        reload_qtd,
        sem_viabilidade,
        atendimento_inviavel,
        feedback_perdemos,
        reativacao
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        vendedor_nome = VALUES(vendedor_nome),
        ligacoes_ativas = VALUES(ligacoes_ativas),
        corporativo_em_negociacao = VALUES(corporativo_em_negociacao),
        corporativo_outros_setores = VALUES(corporativo_outros_setores),
        corporativo_sem_interacao = VALUES(corporativo_sem_interacao),
        vencemos = VALUES(vencemos),
        instalacao_inviavel = VALUES(instalacao_inviavel),
        perdemos = VALUES(perdemos),
        reload_qtd = VALUES(reload_qtd),
        sem_viabilidade = VALUES(sem_viabilidade),
        atendimento_inviavel = VALUES(atendimento_inviavel),
        feedback_perdemos = VALUES(feedback_perdemos),
        reativacao = VALUES(reativacao),
        atualizado_em = CURRENT_TIMESTAMP
      `,
      [
        usuario.id,
        usuario.nome || usuario.usuario || "Vendedor",
        dataReferencia,
        Number(body.ligacoes_ativas || 0),
        Number(body.corporativo_em_negociacao || 0),
        Number(body.corporativo_outros_setores || 0),
        Number(body.corporativo_sem_interacao || 0),
        Number(body.vencemos || 0),
        Number(body.instalacao_inviavel || 0),
        Number(body.perdemos || 0),
        Number(body.reload_qtd || 0),
        Number(body.sem_viabilidade || 0),
        Number(body.atendimento_inviavel || 0),
        body.feedback_perdemos || null,
        body.reativacao || null
      ]
    );

    const [relatorioRows] = await conexao.query(
      `
      SELECT id
      FROM relatorios_reversao_diaria
      WHERE usuario_id = ?
        AND data_referencia = ?
      LIMIT 1
      `,
      [usuario.id, dataReferencia]
    );

    const relatorioId = relatorioRows[0].id;

    await conexao.query(
      `
      DELETE FROM relatorios_reversao_sem_viabilidade
      WHERE relatorio_id = ?
      `,
      [relatorioId]
    );

    for (const item of locais) {
      const localizacao = String(item.localizacao || "").trim();
      const qtd = Number(item.qtd || 0);

      if (!localizacao && !qtd) continue;

      await conexao.query(
        `
        INSERT INTO relatorios_reversao_sem_viabilidade
          (relatorio_id, localizacao, qtd)
        VALUES (?, ?, ?)
        `,
        [relatorioId, localizacao || "-", qtd]
      );
    }

    await conexao.commit();

    return res.json({
      sucesso: true,
      mensagem: "Relatório diário salvo com sucesso."
    });

  } catch (erro) {
    await conexao.rollback();

    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  } finally {
    conexao.release();
  }
});

app.get("/api/relatorio-reversao/equipe", exigirLogin, async (req, res) => {
  try {
    if (!podeVerRelatoriosReversaoEquipe(req)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Você não tem permissão para visualizar os relatórios da equipe."
      });
    }

    const inicio = req.query.inicio || new Date().toISOString().slice(0, 10);
    const fim = req.query.fim || inicio;

    const [relatorios] = await db.query(
      `
      SELECT *
      FROM relatorios_reversao_diaria
      WHERE data_referencia >= ?
        AND data_referencia <= ?
      ORDER BY data_referencia DESC, vendedor_nome ASC
      `,
      [inicio, fim]
    );

    const ids = relatorios.map(item => item.id);

    let locais = [];

    if (ids.length) {
      const [rows] = await db.query(
        `
        SELECT relatorio_id, localizacao, qtd
        FROM relatorios_reversao_sem_viabilidade
        WHERE relatorio_id IN (${ids.map(() => "?").join(",")})
        ORDER BY id ASC
        `,
        ids
      );

      locais = rows;
    }

    const locaisPorRelatorio = {};

    locais.forEach(item => {
      if (!locaisPorRelatorio[item.relatorio_id]) {
        locaisPorRelatorio[item.relatorio_id] = [];
      }

      locaisPorRelatorio[item.relatorio_id].push(item);
    });

    const resultado = relatorios.map(item => {
      const totalLeads =
        Number(item.corporativo_em_negociacao || 0) +
        Number(item.corporativo_outros_setores || 0) +
        Number(item.corporativo_sem_interacao || 0) +
        Number(item.vencemos || 0) +
        Number(item.instalacao_inviavel || 0) +
        Number(item.perdemos || 0) +
        Number(item.reload_qtd || 0) +
        Number(item.sem_viabilidade || 0) +
        Number(item.atendimento_inviavel || 0);

      return {
        ...item,
        total_leads: totalLeads,
        sem_viabilidade_locais: locaisPorRelatorio[item.id] || []
      };
    });

    return res.json({
      sucesso: true,
      periodo: { inicio, fim },
      total: resultado.length,
      relatorios: resultado
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

// COMEÇO DO CÓDIGO DO PORTAL DO CLIENTE //




app.patch("/api/portal-cliente/solicitacoes/:id/aprovar", exigirLogin, async (req, res) => {
  try {
    if (!podeGerenciarPortalCliente(req)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Você não tem permissão para aprovar solicitações do portal."
      });
    }

    const {
      data_aprovada,
      turno_aprovado,
      observacao_interna
    } = req.body || {};

    if (!data_aprovada || !turno_aprovado) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe data e turno aprovados."
      });
    }

    if (!["MANHA", "TARDE"].includes(String(turno_aprovado))) {
      return res.status(400).json({
        erro: true,
        mensagem: "Turno aprovado inválido."
      });
    }

    await db.query(
      `
      UPDATE portal_cliente_agendamentos
      SET
        status = 'APROVADO',
        data_aprovada = ?,
        turno_aprovado = ?,
        observacao_interna = ?,
        aprovado_por_usuario_id = ?,
        aprovado_por_nome = ?,
        aprovado_em = NOW()
      WHERE id = ?
      `,
      [
        data_aprovada,
        turno_aprovado,
        observacao_interna || null,
        req.session.usuario?.id || null,
        req.session.usuario?.nome || req.session.usuario?.usuario || null,
        req.params.id
      ]
    );

    return res.json({
      sucesso: true,
      mensagem: "Solicitação aprovada. Nesta primeira versão, ainda não atualizamos o IXC automaticamente."
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

app.patch("/api/portal-cliente/solicitacoes/:id/recusar", exigirLogin, async (req, res) => {
  try {
    if (!podeGerenciarPortalCliente(req)) {
      return res.status(403).json({
        erro: true,
        mensagem: "Você não tem permissão para recusar solicitações do portal."
      });
    }

    const { motivo_recusa } = req.body || {};

    if (!String(motivo_recusa || "").trim()) {
      return res.status(400).json({
        erro: true,
        mensagem: "Informe o motivo da recusa."
      });
    }

    await db.query(
      `
      UPDATE portal_cliente_agendamentos
      SET
        status = 'RECUSADO',
        motivo_recusa = ?,
        observacao_interna = ?,
        aprovado_por_usuario_id = ?,
        aprovado_por_nome = ?,
        aprovado_em = NOW()
      WHERE id = ?
      `,
      [
        String(motivo_recusa).trim(),
        String(motivo_recusa).trim(),
        req.session.usuario?.id || null,
        req.session.usuario?.nome || req.session.usuario?.usuario || null,
        req.params.id
      ]
    );

    return res.json({
      sucesso: true,
      mensagem: "Solicitação recusada."
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});

app.get("/api/debug-portal-cliente-login", async (req, res) => {
  try {
    const email = normalizarEmail(req.query.email);
    const documento = limparDocumento(req.query.documento).slice(0, 6);

    const retornoEmail = await buscar(
      "cliente",
      "cliente.email",
      email,
      "20"
    );

    const clientesEmail = retornoEmail.registros || [];

    const analisados = clientesEmail.map(cliente => {
      const docIXC = limparDocumento(
        cliente.cnpj_cpf ||
        cliente.cpf_cnpj ||
        cliente.cpf ||
        cliente.cnpj ||
        ""
      );

      const emailIXC = normalizarEmail(
        cliente.email ||
        cliente.email_cobranca ||
        ""
      );

      return {
        id: cliente.id,
        nome: cliente.razao || cliente.nome || cliente.fantasia,
        email_ixc: emailIXC,
        documento_ixc_mascarado: docIXC
          ? `${docIXC.slice(0, 6)}******`
          : null,
        documento_parcial_ixc: docIXC.slice(0, 6),
        documento_parcial_informado: documento,
        email_bate: emailIXC === email,
        documento_bate: docIXC.slice(0, 6) === documento,
        campos_disponiveis: Object.keys(cliente)
      };
    });

    return res.json({
      sucesso: true,
      email_informado: email,
      documento_parcial_informado: documento,
      total_encontrado_por_email: clientesEmail.length,
      analisados,
      bruto_primeiro_cliente: clientesEmail[0] || null
    });

  } catch (erro) {
    return res.status(500).json({
      erro: true,
      mensagem: erro.message
    });
  }
});


piperunRoutes.registrar(app);
inviabilidadeRoutes.registrar(app);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor rodando em http://10.1.103.94:${PORT}`);

  piperunScheduler.iniciar();

});