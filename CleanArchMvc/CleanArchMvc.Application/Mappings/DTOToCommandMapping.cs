using AutoMapper;
using CleanArchMvc.Domain.Entities;
using CleanArchMvc.Application.DTOs;
using CleanArchMvc.Application.Products.Commands;

namespace CleanArchMvc.Application.Mappings
{
        public class DTOToCommandMapping : Profile
        {
            public DTOToCommandMapping()
            {
                CreateMap<ProductDTO, ProductCreateCommand>().ReverseMap();
                CreateMap<ProductDTO, ProductUpdateCommand>().ReverseMap();

            }
        }
}
