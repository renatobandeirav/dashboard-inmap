const equipesComerciais = {
  midia_social: ["11", "42", "151", "220"],

  metropole: ["17", "18", "152", "210", "339", "49"],

  municipios: ["943", "941", "63", "219"]
};

const usuariosDashboard = {
  renato: {
    senha: "123456",
    nome: "Renato Bandeira",
    perfil: "super_admin",
    equipe: null,
    vendedor_id: null,
    permissoes: [
      "ver_comercial",
      "ver_operacional",
      "ver_todos_vendedores",
      "ver_pagamentos",
      "abrir_os",
      "reagendar_os",
      "confirmar_cliente",
      "limpar_confirmacoes",
      "ver_terceirizados",
      "ver_historico",
      "gerenciar_usuarios",
      "exportar_relatorios"
    ]
  },

  coordenacao: {
    senha: "123456",
    nome: "Gerencial / Coordenação",
    perfil: "gerencial",
    equipe: null,
    vendedor_id: null,
    permissoes: [
      "ver_comercial",
      "ver_operacional",
      "ver_todos_vendedores",
      "ver_pagamentos",
      "abrir_os",
      "reagendar_os",
      "confirmar_cliente",
      "limpar_confirmacoes",
      "ver_terceirizados",
      "ver_historico",
      "exportar_relatorios"
    ]
  },

  operacional: {
    senha: "123456",
    nome: "Operacional",
    perfil: "operacional",
    equipe: null,
    vendedor_id: null,
    permissoes: [
      "ver_comercial",
      "ver_operacional",
      "ver_todos_vendedores",
      "ver_pagamentos",
      "abrir_os",
      "reagendar_os",
      "confirmar_cliente",
      "limpar_confirmacoes",
      "ver_terceirizados",
      "ver_historico"
    ]
  },

  supervisao_midia: {
    senha: "123456",
    nome: "Supervisão Mídia Social",
    perfil: "supervisao_comercial",
    equipe: "midia_social",
    vendedor_id: null,
    permissoes: [
      "ver_comercial",
      "ver_equipe"
    ]
  },

  supervisao_metropole: {
    senha: "123456",
    nome: "Supervisão Metrópole",
    perfil: "supervisao_comercial",
    equipe: "metropole",
    vendedor_id: null,
    permissoes: [
      "ver_comercial",
      "ver_equipe"
    ]
  },

  supervisao_municipios: {
    senha: "123456",
    nome: "Supervisão Municípios",
    perfil: "supervisao_comercial",
    equipe: "municipios",
    vendedor_id: null,
    permissoes: [
      "ver_comercial",
      "ver_equipe"
    ]
  },

  vendedor: {
    senha: "123456",
    nome: "Vendedor",
    perfil: "vendedor",
    equipe: null,
    vendedor_id: null,
    permissoes: [
      "ver_comercial",
      "ver_proprio_vendedor"
    ]
  }
};

module.exports = {
  usuariosDashboard,
  equipesComerciais
};