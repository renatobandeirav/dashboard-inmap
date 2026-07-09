require("dotenv").config({ quiet: true });

const axios = require("axios");
const fs = require("fs");
const { vendedores } = require("./nome");

const token = Buffer.from(process.env.IXC_TOKEN).toString("base64");

async function buscarFuncionarios() {
  const response = await axios.post(
    `${process.env.IXC_URL}/funcionarios`,
    {
      qtype: "funcionarios.ativo",
      query: "S",
      oper: "=",
      page: "1",
      rp: "1000",
      sortname: "funcionario",
      sortorder: "asc"
    },
    {
      headers: {
        Authorization: `Basic ${token}`,
        "Content-Type": "application/json",
        ixcsoft: "listar"
      }
    }
  );

  return response.data.registros || [];
}

function gerarObjetoJS(nome, objeto) {
  const linhas = Object.entries(objeto)
    .sort((a, b) => Number(a[0]) - Number(b[0]))
    .map(([id, valor]) => `  "${id}": ${JSON.stringify(valor)}`);

  return `const ${nome} = {\n${linhas.join(",\n")}\n};`;
}

async function main() {
  const funcionarios = await buscarFuncionarios();

  const tecnicos = {};
  const coresTecnicos = {};

  for (const f of funcionarios) {
    if (!f.id || !f.funcionario) continue;

    const id = String(f.id);
    tecnicos[id] = String(f.funcionario).trim().toUpperCase();

    if (f.cor_mapa && String(f.cor_mapa).trim()) {
      coresTecnicos[id] = String(f.cor_mapa).trim();
    }
  }

  tecnicos["0"] = "SEM TÉCNICO";
  tecnicos["16"] = "TERCEIRIZADOS";

  coresTecnicos["0"] = "#94a3b8";
  coresTecnicos["16"] = "#64748b";

  const conteudo = `${gerarObjetoJS("vendedores", vendedores)}

${gerarObjetoJS("tecnicos", tecnicos)}

${gerarObjetoJS("coresTecnicos", coresTecnicos)}

module.exports = {
  vendedores,
  tecnicos,
  coresTecnicos
};
`;

  fs.writeFileSync("nome.js", conteudo, "utf8");

  console.log(`nome.js atualizado com ${Object.keys(tecnicos).length} técnicos.`);
  console.log(`coresTecnicos atualizado com ${Object.keys(coresTecnicos).length} cores.`);
}

main().catch((erro) => {
  console.error("Erro ao atualizar técnicos:");
  console.error(erro.response?.data || erro.message);
});